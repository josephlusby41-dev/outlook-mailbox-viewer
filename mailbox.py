import base64
import hashlib
import json
import html
import os
import re
import secrets
import threading
import time
from urllib.parse import urlencode, urlsplit, unquote, parse_qsl

import requests
import bleach
from bleach.css_sanitizer import CSSSanitizer
from flask import Flask, jsonify, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=bool(os.getenv('RENDER')), MAX_CONTENT_LENGTH=6*1024*1024)
GRAPH = 'https://graph.microsoft.com/v1.0'
TOKEN_EP = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
CLIENT_IDS = ['04b07795-8ddb-461a-bbee-02f9e1bf7b46','1950a258-227b-4e31-a9cf-717495945fc2',
 'd3590ed6-52b3-4102-aeff-aad2292ab01c','ab9b8c07-8f02-4f72-87fa-80105867a763',
 'b26aadf8-566f-4478-926f-589f601d9c74','27922004-16b8-4a39-9745-afe3546f733d',
 '27922004-5251-4030-b22d-91ecd9a37ea4']
STORE = {}
STORE_LOCK = threading.RLock()
PUBLIC_URL = os.getenv('PUBLIC_URL','https://outlook-mailbox-viewer.onrender.com').rstrip('/')
OAUTH_CLIENT = os.getenv('MICROSOFT_CLIENT_ID','')
OAUTH_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET','')
SCOPES = 'offline_access User.Read Mail.ReadWrite Mail.Send Calendars.ReadWrite Contacts.ReadWrite MailboxSettings.ReadWrite'

class ApiError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status
        self.code = 'request_failed'
        self.feature = None
        self.required = []
        self.details = {}

def token_request(values):
    r = requests.post(TOKEN_EP, data=values, timeout=20)
    try:
        data = r.json()
    except ValueError:
        raise ApiError('Microsoft returned an unreadable sign-in response.',502)
    if not r.ok:
        code = data.get('error','invalid_token')
        raise ApiError('Microsoft sign-in failed ('+code+'). Check the token, its original client ID, or your tenant policy.',401)
    if not data.get('access_token'):
        raise ApiError('Microsoft did not return an access token.',502)
    return data

def save_login(data, cid, refresh='', managed=False):
    with STORE_LOCK:
        now = time.time()
        for sid, old in list(STORE.items()):
            if now-old['used'] > 7200:
                STORE.pop(sid,None)
        STORE.pop(session.get('sid'),None)
        session.clear()
        sid = secrets.token_urlsafe(32)
        session.update(sid=sid, csrf=secrets.token_urlsafe(32))
        STORE[sid] = dict(access=data['access_token'], refresh=data.get('refresh_token') or refresh,
            cid=cid, managed=managed, scopes=data.get('scope'), used=now, expires=now+int(data.get('expires_in',3600)), lock=threading.RLock())

def account():
    with STORE_LOCK:
        t = STORE.get(session.get('sid'))
        if not t or time.time()-t['used'] > 7200:
            STORE.pop(session.get('sid'),None)
            raise ApiError('Your session expired. Sign in again.',401)
        t['used'] = time.time()
        return t

def renew(t):
    if not t['refresh']:
        raise ApiError('Access token expired. Sign in again with a fresh token.',401)
    values = dict(client_id=t['cid'],grant_type='refresh_token',refresh_token=t['refresh'])
    if t['managed']:
        values['scope'] = t.get('scopes') or SCOPES
        if OAUTH_SECRET:
            values['client_secret'] = OAUTH_SECRET
    else:
        values['scope'] = 'https://graph.microsoft.com/.default offline_access'
    data = token_request(values)
    t.update(access=data['access_token'],refresh=data.get('refresh_token') or t['refresh'],
             scopes=data.get('scope') or t.get('scopes'),
             expires=time.time()+int(data.get('expires_in',3600)))

@app.before_request
def guard():
    if request.method in ('POST','PATCH','DELETE'):
        expected = session.get('csrf','')
        supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf','')
        if not expected or not secrets.compare_digest(expected,supplied):
            raise ApiError('Form expired. Reload the page and try again.',400)

@app.after_request
def privacy(response):
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
        'Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'})
    return response

@app.errorhandler(ApiError)
def api_error(e):
    return jsonify(error=e.message,code=e.code,feature=e.feature,required=e.required,details=e.details),e.status

@app.errorhandler(requests.RequestException)
def network_error(e):
    return jsonify(error='Microsoft could not be reached. Please retry.'),502

# Scope hints are for the interface only. Microsoft Graph enforces authorization.
# Never treat decoded JWT hints as verified credentials.
FEATURE_SCOPES = {
    'mail_read': ['Mail.Read','Mail.ReadWrite'],
    'mail_write': ['Mail.ReadWrite'],
    'mail_send': ['Mail.Send'],
    'rules_read': ['MailboxSettings.Read','MailboxSettings.ReadWrite'],
    'rules_write': ['MailboxSettings.ReadWrite'],
    'settings': ['MailboxSettings.ReadWrite'],
    'calendar': ['Calendars.ReadWrite'],
    'contacts': ['Contacts.ReadWrite'],
    'tasks': ['Tasks.ReadWrite'],
    'groups': ['GroupMember.Read.All','Directory.Read.All'],
}

def permission_for(path,method):
    if 'messageRules' in path:
        return 'inbox rules', FEATURE_SCOPES['rules_read' if method=='GET' else 'rules_write']
    if 'mailboxSettings' in path:
        return 'mailbox settings', ['MailboxSettings.Read' if method=='GET' else 'MailboxSettings.ReadWrite']
    if '/todo' in path:
        return 'Microsoft To Do', FEATURE_SCOPES['tasks']
    if '/memberOf' in path:
        return 'group memberships', FEATURE_SCOPES['groups']
    if any(x in path for x in ['/events','/calendar']):
        return 'calendar', ['Calendars.Read' if method=='GET' else 'Calendars.ReadWrite']
    if '/contacts' in path:
        return 'contacts', ['Contacts.Read' if method=='GET' else 'Contacts.ReadWrite']
    if path.endswith('/sendMail') or path.endswith('/send') or path.endswith('/reply') or path.endswith('/replyAll') or path.endswith('/forward'):
        return 'sending mail', ['Mail.Send']
    return ('reading mail',['Mail.Read','Mail.ReadWrite']) if method=='GET' else ('managing mail',['Mail.ReadWrite'])

def scope_hints(t):
    if t.get('scopes'):
        return [x.removeprefix('https://graph.microsoft.com/') for x in t['scopes'].split()]
    try:
        raw=t['access'].split('.')[1]
        data=json.loads(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)))
        scopes=data.get('scp')
        return scopes.split() if isinstance(scopes,str) else None
    except (ValueError,IndexError,UnicodeDecodeError,TypeError):
        return None

@app.get('/api/session')
def session_info():
    t=account()
    scopes=scope_hints(t)
    capabilities={name:{'state':'unknown' if scopes is None else ('available' if any(s in scopes for s in required) else 'missing'),
                        'required':required} for name,required in FEATURE_SCOPES.items()}
    return {'capabilities':capabilities,'scopes':scopes,'oauth':bool(OAUTH_CLIENT),
            'refreshEnabled':bool(t['refresh']),'expiresAt':t['expires']}

SAFE_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | set('p div span br hr h1 h2 h3 h4 h5 h6 table thead tbody tfoot tr td th colgroup col img font blockquote pre code ul ol li sup sub center strike s u caption'.split())
CSS = CSSSanitizer(allowed_css_properties=['color','background-color','font-family','font-size','font-weight','font-style','text-align','text-decoration','line-height','padding','margin','border','border-collapse','width','max-width','height','vertical-align','white-space'])

def link_scheme(value):
    try:
        return urlsplit(value.strip()).scheme.lower()
    except ValueError:
        return ''

def safe_attribute(tag,name,value):
    if name=='style':
        return True
    if tag=='a':
        return name in ('href','title') and (name!='href' or link_scheme(value) in ('http','https','mailto','tel'))
    if tag=='img':
        return name in ('alt','width','height') or (name=='src' and (link_scheme(value) in ('http','https') or bool(re.fullmatch(r'data:image/(?:png|gif|jpeg|webp|bmp|avif);base64,[A-Za-z0-9+/=\s]+',value))))
    return name in ('title','align','valign','colspan','rowspan','width','height','border','cellpadding','cellspacing','color','face','size')

def safe_link(attrs,new=False):
    href=attrs.get((None,'href'),'').strip()
    if link_scheme(href) not in ('http','https','mailto','tel'):
        return None
    attrs[(None,'target')]='_blank'
    attrs[(None,'rel')]='noopener noreferrer'
    return attrs

def safe_message_body(body, images=None):
    source=body.get('content') or ''
    if images:
        source=re.sub(r'''cid:([^\s<>"']+)''', lambda match:images.get(unquote(html.unescape(match.group(1))).strip('<>').casefold(),match.group(0)),source,flags=re.I)
    if body.get('contentType','').lower()!='html':
        source='<pre>'+html.escape(source)+'</pre>'
    # Drop executable/active containers completely before retaining ordinary formatting.
    source=re.sub(r'<(script|style|iframe|object|svg|math|form)\b[^>]*>.*?</\1\s*>','',source,flags=re.I|re.S)
    cleaned=bleach.clean(source,tags=SAFE_TAGS,attributes=safe_attribute,
        protocols=['http','https','mailto','tel','data'],css_sanitizer=CSS,strip=True)
    return bleach.linkifier.Linker(callbacks=[safe_link],skip_tags=['code'],parse_email=True).linkify(cleaned)

def embedded_message_images(path, body):
    source=body.get('content') or ''
    wanted={unquote(html.unescape(cid)).strip('<>').casefold() for cid in re.findall(r"cid:([^\s<>\"']+)",source,flags=re.I)}
    if not wanted:
        return {},False
    images={}
    total=0
    data=graph_request('GET',path+'/attachments',{'$top':100})
    for page in range(20):
        for attachment in data.get('value',[]):
            cid=(attachment.get('contentId') or '').strip('<>').casefold()
            if cid not in wanted:
                continue
            mime=(attachment.get('contentType') or '').split(';')[0].lower()
            if mime not in ('image/png','image/jpeg','image/gif','image/webp','image/bmp','image/avif'):
                continue
            encoded=attachment.get('contentBytes')
            if not encoded and attachment.get('id'):
                detail=graph_request('GET',path+'/attachments/'+requests.utils.quote(attachment['id'],safe=''))
                encoded=detail.get('contentBytes')
            if not isinstance(encoded,str) or len(encoded)>16*1024*1024 or total+len(encoded)>32*1024*1024:
                continue
            encoded=re.sub(r'\s+','',encoded)
            try:
                base64.b64decode(encoded,validate=True)
            except ValueError:
                continue
            images[cid]='data:'+mime+';base64,'+encoded
            total+=len(encoded)
        if wanted.issubset(images) or not data.get('@odata.nextLink'):
            break
        link=urlsplit(data['@odata.nextLink'])
        if link.scheme!='https' or link.netloc!='graph.microsoft.com' or not link.path.startswith('/v1.0'+path+'/attachments'):
            break
        data=graph_request('GET',link.path[len('/v1.0'):],dict(parse_qsl(link.query)))
    return images,not wanted.issubset(images)

@app.get('/health')
def health():
    return {'status':'ok'}

@app.get('/')
def home():
    session.setdefault('csrf',secrets.token_urlsafe(32))
    with open(os.path.join(os.path.dirname(__file__),'index.html'),encoding='utf-8') as f:
        page = f.read()
    connected = False
    try:
        account(); connected=True
    except ApiError:
        pass
    return render_template_string(page, csrf=session['csrf'], connected=connected,
                                  client_ids=CLIENT_IDS, oauth=bool(OAUTH_CLIENT))

@app.post('/login')
def login():
    values = request.get_json(silent=True) or {}
    token = values.get('token','').strip()
    cid = values.get('client_id','')
    if not token:
        raise ApiError('Enter a token.')
    if values.get('kind') == 'access':
        data = {'access_token':token}
    else:
        if cid not in CLIENT_IDS:
            raise ApiError('Select the client ID that issued your refresh token.')
        data = token_request(dict(client_id=cid,grant_type='refresh_token',refresh_token=token,
                                 scope='https://graph.microsoft.com/.default offline_access'))
    save_login(data,cid,token if values.get('kind')!='access' else '')
    return {'ok':True}

@app.post('/logout')
def logout():
    with STORE_LOCK:
        STORE.pop(session.get('sid'),None)
    session.clear()
    return {'ok':True}

@app.get('/auth/microsoft')
def microsoft_login():
    if not OAUTH_CLIENT:
        raise ApiError('Microsoft application registration is not configured.')
    state=secrets.token_urlsafe(32)
    verifier=secrets.token_urlsafe(64)
    extra={'tasks':'Tasks.ReadWrite','groups':'GroupMember.Read.All','shared':'Mail.ReadWrite.Shared Mail.Send.Shared Calendars.ReadWrite.Shared Contacts.ReadWrite.Shared'}
    requested_scopes=SCOPES+' '+extra.get(request.args.get('feature'),'')
    session.update(oauth_state=state,verifier=verifier,requested_scopes=requested_scopes)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?'+urlencode(dict(
        client_id=OAUTH_CLIENT,response_type='code',redirect_uri=PUBLIC_URL+'/auth/callback',
        scope=requested_scopes,prompt='select_account',state=state,code_challenge=challenge,code_challenge_method='S256')))

@app.get('/auth/callback')
def callback():
    state=session.pop('oauth_state','')
    verifier=session.pop('verifier','')
    requested_scopes=session.pop('requested_scopes',SCOPES)
    if not state or not secrets.compare_digest(state,request.args.get('state','')):
        raise ApiError('Sign-in state expired. Start sign-in again.')
    if not request.args.get('code'):
        raise ApiError('Microsoft sign-in was cancelled or denied.',401)
    values=dict(client_id=OAUTH_CLIENT,grant_type='authorization_code',code=request.args['code'],
                code_verifier=verifier,redirect_uri=PUBLIC_URL+'/auth/callback',scope=requested_scopes)
    if OAUTH_SECRET:
        values['client_secret']=OAUTH_SECRET
    data=token_request(values)
    save_login(data,OAUTH_CLIENT,managed=True)
    return redirect('/')

# The browser never receives credentials. Only these Microsoft Graph resource families are allowed.
RESOURCE = re.compile(r'^/(?:me|users/[^/]+)(?:/(?:mailFolders|messages|sendMail|mailboxSettings|outlook|events|calendarView|calendars|calendar|contacts|contactFolders|people|todo|memberOf|findMeetingTimes|getSchedule)(?:/.*)?)?$')

def valid_path(path):
    if not isinstance(path,str) or not RESOURCE.fullmatch(path) or '..' in path or '?' in path or '#' in path or '\\' in path:
        raise ApiError('This Microsoft Graph resource is not enabled.')
    return path

def graph_request(method,path,query=None,payload=None,binary=False):
    valid_path(path)
    t=account()
    with t['lock']:
        if t['refresh'] and time.time() >= t['expires']-90:
            renew(t)
        for attempt in range(2):
            r=requests.request(method,GRAPH+path,params=query or {},json=payload,
                headers={'Authorization':'Bearer '+t['access'],
                         'Prefer':'outlook.body-content-type="html"'},timeout=25)
            if r.status_code==401 and attempt==0:
                renew(t); continue
            if not r.ok:
                try:
                    err=r.json().get('error',{})
                    message=err.get('message','Microsoft rejected this operation.')
                    code=err.get('code','GraphError')
                except ValueError:
                    message,code='Microsoft rejected this operation.','GraphError'
                    err={}
                if r.status_code==403:
                    feature, required = permission_for(path,method)
                    error=ApiError('Microsoft denied the '+feature+' request. '+message,403)
                    error.code='permission_required';error.feature=feature;error.required=required
                    inner=err.get('innerError',{}) if isinstance(err,dict) else {}
                    headers=r.headers if isinstance(r.headers,dict) or hasattr(r.headers,'items') else {}
                    request_id=headers.get('request-id') or (inner.get('request-id') if isinstance(inner,dict) else None)
                    error.details={'graphCode':code,'method':method,'path':path,'requestId':request_id if isinstance(request_id,str) else None,'scopeHint':scope_hints(t)}
                    raise error
                raise ApiError(code+': '+message,r.status_code)
            if binary:
                return r.content,r.headers.get('Content-Type','application/octet-stream')
            if not r.content:
                return {}
            try:
                data=r.json()
                if isinstance(data,dict) and isinstance(data.get('body'),dict):
                    images={}
                    if method=='GET' and re.fullmatch(r'/(?:me|users/[^/]+)/messages/[^/]+',path):
                        try:
                            images,missing=embedded_message_images(path,data['body'])
                            if missing:
                                data['imageNotice']='Some embedded images were unavailable or use an unsupported image format.'
                        except (ApiError,requests.RequestException):
                            data['imageNotice']='Some embedded pictures could not be retrieved. You can still read this message.'
                    data['safeBody']=safe_message_body(data['body'],images)
                return data
            except ValueError:
                raise ApiError('Microsoft returned an unexpected response.',502)

@app.post('/api/graph')
def graph_api():
    body=request.get_json(silent=True) or {}
    method=body.get('method','GET').upper()
    if method not in ('GET','POST','PATCH','DELETE'):
        raise ApiError('Unsupported request method.')
    return jsonify(graph_request(method,body.get('path',''),body.get('query'),body.get('payload')))

@app.post('/api/download')
def download():
    body=request.get_json(silent=True) or {}
    path=body.get('path','')
    if not re.fullmatch(r'/(?:me|users/[^/]+)/messages/[^/]+(?:/attachments/[^/]+)?/\$value',path):
        raise ApiError('Invalid download path.')
    content,kind=graph_request('GET',path,binary=True)
    name=re.sub(r'[^a-zA-Z0-9._ -]','_',body.get('name','download'))[:120]
    response=app.response_class(content,content_type=kind)
    response.headers['Content-Disposition']='attachment; filename="'+name+'"'
    return response

@app.get('/source.zip')
def source_zip():
    if os.getenv('ENABLE_SOURCE_DOWNLOAD') != '1':
        raise ApiError('Source download is available only in the development preview.',404)
    import io, zipfile
    buffer=io.BytesIO()
    root=os.path.dirname(__file__)
    with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as z:
        for name in ['mailbox.py','index.html','requirements.txt','README.txt','FEATURES.txt']:
            with open(os.path.join(root,name),'rb') as f:
                z.writestr('outlook-mailbox/'+name,f.read())
    response=app.response_class(buffer.getvalue(),content_type='application/zip')
    response.headers['Content-Disposition']='attachment; filename="outlook-mailbox.zip"'
    return response

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.getenv('PORT','10000')))
