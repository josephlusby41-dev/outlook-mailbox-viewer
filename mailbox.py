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

# These are the client IDs we rotate through for refreshes.
# Some are more permissive than others regarding scope expansion.
CLIENT_IDS = [
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46',  # Azure CLI
    '1950a258-227b-4e31-a9cf-717495945fc2',  # Azure PowerShell
    'd3590ed6-52b3-4102-aeff-aad2292ab01c',  # Microsoft Office
    '27922004-5251-4030-b22d-91ecd9a37ea4',  # Outlook Mobile
    'ab9b8c07-8f02-4f72-87fa-80105867a763',  # OneDrive
    'b26aadf8-566f-4478-926f-589f601d9c74',  # Microsoft Teams
    '27922004-16b8-4a39-9745-afe3546f733d'   # Windows Store
]

STORE = {}
STORE_LOCK = threading.RLock()
PUBLIC_URL = os.getenv('PUBLIC_URL','https://outlook-mailbox-viewer.onrender.com').rstrip('/')
OAUTH_CLIENT = os.getenv('MICROSOFT_CLIENT_ID','')
OAUTH_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET','')

# Explicitly request these scopes. Note: MailboxSettings.ReadWrite is critical for Rules.
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
        desc = data.get('error_description','')
        raise ApiError(f'Microsoft sign-in failed ({code}): {desc}',401)
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
    
    # Try to refresh with explicit scopes first. If that fails, try .default.
    # We rotate client IDs to find one that accepts the refresh with our desired scopes.
    last_error = None
    for cid in CLIENT_IDS:
        values = dict(client_id=cid, grant_type='refresh_token', refresh_token=t['refresh'])
        
        # For managed OAuth apps, we use the stored scopes. For stolen tokens, we try to force our desired scopes.
        if t['managed']:
            values['scope'] = t.get('scopes') or SCOPES
            if OAUTH_SECRET:
                values['client_secret'] = OAUTH_SECRET
        else:
            # Try explicit scopes first
            values['scope'] = SCOPES
        
        try:
            data = token_request(values)
            # Success! Update the token and the client ID used for future refreshes
            t.update(access=data['access_token'], 
                     refresh=data.get('refresh_token') or t['refresh'],
                     cid=cid, # Update CID to the one that worked
                     scopes=data.get('scope') or t.get('scopes'),
                     expires=time.time()+int(data.get('expires_in',3600)))
            return
        except ApiError as e:
            last_error = e
            # If it's an invalid_grant or unauthorized_client, try next CID
            if 'invalid_grant' in e.message or 'unauthorized_client' in e.message:
                continue
            # If it's a scope error, we might need to try .default as fallback for some CIDs
            if 'AADSTS65001' in e.message or 'permission' in e.message.lower():
                # Try fallback to .default for this specific CID if explicit failed
                if not t['managed']:
                    try:
                        values['scope'] = 'https://graph.microsoft.com/.default offline_access'
                        data = token_request(values)
                        t.update(access=data['access_token'], 
                                 refresh=data.get('refresh_token') or t['refresh'],
                                 cid=cid,
                                 scopes=data.get('scope') or t.get('scopes'),
                                 expires=time.time()+int(data.get('expires_in',3600)))
                        return
                    except ApiError:
                        pass
            continue
            
    # If all CIDs failed
    raise last_error or ApiError('Failed to refresh token with any known client ID.', 401)

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
        return images, True

# ---------- Graph plumbing ----------

def _graph_once(method, path, params=None, body=None, token=None):
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    r = requests.request(
        method, GRAPH + path,
        params={k: v for k, v in (params or {}).items() if v not in (None, '')},
        data=json.dumps(body) if body is not None else None,
        headers=headers, timeout=30,
    )
    if r.status_code == 204 or not r.content:
        if r.ok:
            return {}
        raise ApiError(f'Microsoft returned HTTP {r.status_code}.', 502)
    try:
        data = r.json()
    except ValueError:
        raise ApiError(f'Microsoft returned unreadable data (HTTP {r.status_code}).', 502)
    if r.ok:
        return data
    inner = (data.get('error') or {})
    code = inner.get('code', 'UnknownError')
    msg = inner.get('message', '') or f'HTTP {r.status_code}'
    feature, required = permission_for(path, method)
    if r.status_code == 403:
        e = ApiError(f'{msg} (Graph refuses {method} {path}; this token likely lacks {", ".join(required)}.)', 403)
        e.code = code
        e.feature = feature
        e.required = required
        e.details = {'path': path, 'method': method}
        raise e
    if r.status_code == 401:
        raise ApiError('Microsoft rejected the access token. Sign in again.', 401)
    if r.status_code == 404:
        raise ApiError('That item no longer exists in the mailbox.', 404)
    raise ApiError(msg, r.status_code if r.status_code < 500 else 502)


def graph_request(method, path, params=None, body=None):
    """Issue one Graph call, refreshing the token once on a 401."""
    t = account()
    if time.time() >= t['expires'] - 30 and t['refresh']:
        with t['lock']:
            if time.time() >= t['expires'] - 30:
                renew(t)
    try:
        return _graph_once(method, path, params, body, t['access'])
    except ApiError as e:
        # One retry with a forced refresh — covers tenant-side token revocation timing.
        if e.status != 401 or not t['refresh']:
            raise
        with t['lock']:
            renew(t)
        return _graph_once(method, path, params, body, t['access'])


def paged(path, params, limit=50):
    """Walk @odata.nextLink, capped at `limit` items, keeping the next cursor."""
    items, cursor = [], None
    data = graph_request('GET', path, params)
    while True:
        items.extend(data.get('value', []))
        nxt = data.get('@odata.nextLink')
        if not nxt or len(items) >= limit:
            if nxt:
                link = urlsplit(nxt)
                if link.netloc == 'graph.microsoft.com' and link.path.startswith('/v1.0'+path):
                    cursor = link.query
            break
        link = urlsplit(nxt)
        if link.netloc != 'graph.microsoft.com' or not link.path.startswith('/v1.0'+path):
            break
        data = graph_request('GET', link.path[len('/v1.0'):], dict(parse_qsl(link.query)))
    return items[:limit], cursor

# ---------- Routes: session token ingestion ----------

CSRF_EXEMPT = {'/token', '/callback', '/login'}

@app.before_request
def _csrf_guard():
    if request.path in CSRF_EXEMPT:
        return
    if request.method in ('POST', 'PATCH', 'DELETE'):
        expected = session.get('csrf', '')
        supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf', '') or \
                   ((request.get_json(silent=True) or {}).get('csrf') if request.is_json else '')
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            raise ApiError('Form expired. Reload the page and try again.', 400)


@app.get('/')
def index():
    return INDEX_HTML.replace('__CSRF__', session.get('csrf', '')), 200, {
        'Content-Type': 'text/html; charset=utf-8'}


@app.get('/token')
def token_form():
    return TOKEN_HTML.replace('__ERROR__', ''), 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.post('/token')
def token_ingest():
    access = (request.form.get('access_token') or '').strip()
    refresh = (request.form.get('refresh_token') or '').strip()
    cid = (request.form.get('client_id') or CLIENT_IDS[0]).strip()

    if not access and refresh:
        probe = dict(client_id=cid, grant_type='refresh_token',
                     refresh_token=refresh, scope=SCOPES)
        try:
            data = token_request(probe)
        except ApiError as e:
            return TOKEN_HTML.replace('__ERROR__', html.escape(e.message)), 200, {
                'Content-Type': 'text/html; charset=utf-8'}
        save_login(data, cid, refresh=refresh, managed=False)
        return redirect('/')

    if not access:
        return TOKEN_HTML.replace('__ERROR__', 'Paste an access token or a refresh token.'), 200, {
            'Content-Type': 'text/html; charset=utf-8'}

    try:
        who = _graph_once('GET', '/me', {'$select': 'id,displayName,mail,userPrincipalName'},
                          token=access)
    except ApiError as e:
        return TOKEN_HTML.replace('__ERROR__', html.escape(e.message)), 200, {
            'Content-Type': 'text/html; charset=utf-8'}

    save_login({'access_token': access, 'refresh_token': refresh or None,
                'expires_in': 3600, 'scope': None}, cid, refresh=refresh, managed=False)
    session['who'] = who.get('mail') or who.get('userPrincipalName') or who.get('displayName')
    return redirect('/')


@app.post('/api/logout')
def logout():
    with STORE_LOCK:
        STORE.pop(session.get('sid'), None)
    session.clear()
    return {'ok': True}


@app.get('/api/session')
def session_view():
    t = account()
    scopes = scope_hints(t)
    caps = {}
    for name, required in FEATURE_SCOPES.items():
        if scopes is None:
            state = 'unknown'
        elif name == 'rules_write':
            state = 'available' if 'MailboxSettings.ReadWrite' in scopes else 'missing'
        else:
            state = 'available' if any(s in scopes for s in required) else 'missing'
        caps[name] = {'state': state, 'required': required}
    return {'capabilities': caps, 'scopes': scopes, 'refreshEnabled': bool(t['refresh']),
            'expiresAt': t['expires'], 'clientId': t['cid'],
            'who': session.get('who')}


@app.get('/api/debug')
def debug_view():
    """Everything you need to diagnose a 403 in one screen."""
    t = account()
    me, note = {}, None
    try:
        me = graph_request('GET', '/me', {'$select': 'id,displayName,mail,userPrincipalName'})
    except ApiError as e:
        note = e.message
    rules_ok, rules_note = None, None
    try:
        graph_request('GET', '/me/messageRules')
        rules_ok = True
    except ApiError as e:
        rules_ok = False
        rules_note = f'{e.message} | required: {", ".join(e.required)}'
    return {'who': session.get('who'), 'me': me, 'meError': note,
            'scopes': scope_hints(t), 'clientId': t['cid'], 'managed': t['managed'],
            'hasRefresh': bool(t['refresh']), 'expiresIn': int(t['expires'] - time.time()),
            'rulesReadable': rules_ok, 'rulesError': rules_note}

# ---------- Routes: mail ----------

MAIL_SELECT = ('id,conversationId,subject,bodyPreview,isRead,isDraft,hasAttachments,'
               'importance,receivedDateTime,sentDateTime,webLink,flag,'
               'from,sender,toRecipients,ccRecipients,bccRecipients')


@app.get('/api/messages')
def messages():
    folder = request.args.get('folder', 'inbox')
    search = request.args.get('search', '').strip()
    params = {'$top': 50, '$select': MAIL_SELECT,
              '$orderby': 'receivedDateTime desc'}
    if search:
        params['$search'] = f'"{search}"'
        params.pop('$orderby', None)
    path = '/me/messages' if folder in ('all', '') else f'/me/mailFolders/{folder}/messages'
    items, cursor = paged(path, params, 50)
    for m in items:
        m['bodyPreview'] = (m.get('bodyPreview') or '')[:180]
    return {'messages': items, 'cursor': cursor}


@app.get('/api/messages/<mid>')
def message_detail(mid):
    mid = requests.utils.quote(mid, safe='')
    path = f'/me/messages/{mid}'
    data = graph_request('GET', path, {'$select': MAIL_SELECT.replace(
        'bodyPreview', 'bodyPreview,body')})
    images, _ = embedded_message_images(path, data.get('body') or {})
    data['safeHtml'] = safe_message_body(data.get('body') or {}, images)
    data.pop('body', None)
    return data


@app.delete('/api/messages/<mid>')
def message_delete(mid):
    graph_request('DELETE', f'/me/messages/{requests.utils.quote(mid, safe="")}')
    return {'ok': True}


@app.post('/api/messages/<mid>/move')
def message_move(mid):
    dest = (request.get_json(silent=True) or {}).get('destinationId', 'archive')
    out = graph_request('POST', f'/me/messages/{requests.utils.quote(mid, safe="")}/move',
                        body={'destinationId': dest})
    return {'ok': True, 'id': out.get('id')}


@app.post('/api/messages/<mid>/read')
def message_read(mid):
    value = bool((request.get_json(silent=True) or {}).get('isRead', True))
    graph_request('PATCH', f'/me/messages/{requests.utils.quote(mid, safe="")}',
                  body={'isRead': value})
    return {'ok': True, 'isRead': value}


@app.get('/api/folders')
def folders():
    items, _ = paged('/me/mailFolders', {'$top': 100,
                                        '$select': 'id,displayName,totalItemCount,unreadItemCount'}, 100)
    return {'folders': items}


@app.post('/api/send')
def send_mail():
    p = request.get_json(silent=True) or {}
    to = [x.strip() for x in (p.get('to') or '').split(',') if x.strip()]
    if not to:
        raise ApiError('Add at least one recipient.', 400)
    msg = {
        'subject': p.get('subject') or '(no subject)',
        'body': {'contentType': 'HTML', 'content': bleach.clean(
            p.get('body') or '', tags=SAFE_TAGS, strip=True, css_sanitizer=CSS)},
        'toRecipients': [{'emailAddress': {'address': a}} for a in to],
    }
    if p.get('cc'):
        msg['ccRecipients'] = [{'emailAddress': {'address': a.strip()}}
                               for a in p['cc'].split(',') if a.strip()]
    graph_request('POST', '/me/sendMail', body={'message': msg, 'saveToSentItems': True})
    return {'ok': True}

# ---------- Routes: inbox rules (the part that was failing) ----------

RULE_SELECT = ('id,displayName,sequence,isEnabled,conditions,actions,exceptions')


@app.get('/api/rules')
def rules_list():
    try:
        data = graph_request('GET', '/me/messageRules')
    except ApiError as e:
        if e.status == 403:
            e.feature = 'inbox rules'
            e.required = ['MailboxSettings.Read' , 'MailboxSettings.ReadWrite']
            e.details = {'hint': 'Token needs MailboxSettings.ReadWrite consented at device-code time.'}
        raise
    return {'rules': data.get('value', [])}


@app.post('/api/rules')
def rules_create():
    p = request.get_json(silent=True) or {}
    name = (p.get('displayName') or '').strip()
    if not name:
        raise ApiError('Give the rule a name.', 400)

    conditions = {}
    sender = (p.get('fromContains') or '').strip()
    subject = (p.get('subjectContains') or '').strip()
    body_ = (p.get('bodyContains') or '').strip()
    if sender:
        conditions['senderContains'] = [sender]
    if subject:
        conditions['subjectContains'] = [subject]
    if body_:
        conditions['bodyContains'] = [body_]
    if not conditions:
        raise ApiError('A rule needs at least one condition.', 400)

    actions = {}
    folder = (p.get('moveTo') or '').strip()
    forward = (p.get('forwardTo') or '').strip()
    delete = bool(p.get('delete'))
    mark_read = bool(p.get('markRead'))
    if folder:
        actions['moveToFolder'] = folder if re.fullmatch(r'[A-Za-z0-9=_-]{20,}', folder) \
            else _folder_id_by_name(folder)
    if forward:
        actions['forwardTo'] = [{'emailAddress': {'address': forward}}]
    if delete:
        actions['delete'] = True
    if mark_read:
        actions['markAsRead'] = True
    if not actions:
        raise ApiError('A rule needs at least one action.', 400)

    payload = {'displayName': name, 'sequence': int(p.get('sequence') or 1),
               'isEnabled': True, 'conditions': conditions, 'actions': actions}
    out = graph_request('POST', '/me/messageRules', body=payload)
    return {'ok': True, 'rule': out}


@app.patch('/api/rules/<rid>')
def rules_update(rid):
    rid = requests.utils.quote(rid, safe='')
    p = request.get_json(silent=True) or {}
    body = {k: p[k] for k in ('displayName', 'isEnabled', 'sequence') if k in p}
    if 'conditions' in p:
        body['conditions'] = p['conditions']
    if 'actions' in p:
        body['actions'] = p['actions']
    if not body:
        raise ApiError('Nothing to change.', 400)
    out = graph_request('PATCH', f'/me/messageRules/{rid}', body=body)
    return {'ok': True, 'rule': out}


@app.delete('/api/rules/<rid>')
def rules_delete(rid):
    graph_request('DELETE', f'/me/messageRules/
