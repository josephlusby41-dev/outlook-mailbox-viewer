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
from flask import (
    Flask, jsonify, redirect, render_template_string, request, session
)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=bool(os.getenv('RENDER')),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)

GRAPH = 'https://graph.microsoft.com/v1.0'
TOKEN_EP = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

CLIENT_IDS = [
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
    '1950a258-227b-4e31-a9cf-717495945fc2',
    'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    'ab9b8c07-8f02-4f72-87fa-80105867a763',
    'b26aadf8-566f-4478-926f-589f601d9c74',
    '27922004-16b8-4a39-9745-afe3546f733d',
    '27922004-5251-4030-b22d-91ecd9a37ea4',
]

STORE = {}
STORE_LOCK = threading.RLock()

PUBLIC_URL = os.getenv(
    'PUBLIC_URL', 'https://outlook-mailbox-viewer.onrender.com'
).rstrip('/')

OAUTH_CLIENT = os.getenv('MICROSOFT_CLIENT_ID', '')
OAUTH_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET', '')

SCOPES = (
    'offline_access User.Read Mail.ReadWrite Mail.Send '
    'Calendars.ReadWrite Contacts.ReadWrite MailboxSettings.ReadWrite'
)


class ApiError(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status
        self.code = 'request_failed'
        self.feature = None
        self.required = []
        self.details = {}


def token_request(values):
    response = requests.post(TOKEN_EP, data=values, timeout=20)

    try:
        data = response.json()
    except ValueError:
        raise ApiError(
            'Microsoft returned an unreadable sign-in response.', 502
        )

    if not response.ok:
        code = data.get('error', 'invalid_token')
        raise ApiError(
            'Microsoft sign-in failed (' + code + '). Check the token, '
            'its original client ID, or your tenant policy.',
            401,
        )

    if not data.get('access_token'):
        raise ApiError('Microsoft did not return an access token.', 502)

    return data


def save_login(data, cid, refresh='', managed=False):
    with STORE_LOCK:
        now = time.time()

        for sid, old in list(STORE.items()):
            if now - old['used'] > 7200:
                STORE.pop(sid, None)

        STORE.pop(session.get('sid'), None)
        session.clear()

        sid = secrets.token_urlsafe(32)
        session.update(sid=sid, csrf=secrets.token_urlsafe(32))

        STORE[sid] = {
            'access': data['access_token'],
            'refresh': data.get('refresh_token') or refresh,
            'cid': cid,
            'managed': managed,
            'scopes': data.get('scope'),
            'used': now,
            'expires': now + int(data.get('expires_in', 3600)),
            'lock': threading.RLock(),
        }


def account():
    with STORE_LOCK:
        record = STORE.get(session.get('sid'))

        if not record or time.time() - record['used'] > 7200:
            STORE.pop(session.get('sid'), None)
            raise ApiError('Your session expired. Sign in again.', 401)

        record['used'] = time.time()
        return record


def renew(record):
    if not record['refresh']:
        raise ApiError(
            'Access token expired. Sign in again with a fresh token.', 401
        )

    values = {
        'client_id': record['cid'],
        'grant_type': 'refresh_token',
        'refresh_token': record['refresh'],
    }

    if record['managed']:
        values['scope'] = record.get('scopes') or SCOPES

        if OAUTH_SECRET:
            values['client_secret'] = OAUTH_SECRET
    else:
        values['scope'] = 'https://graph.microsoft.com/.default offline_access'

    data = token_request(values)

    record.update(
        access=data['access_token'],
        refresh=data.get('refresh_token') or record['refresh'],
        scopes=data.get('scope') or record.get('scopes'),
        expires=time.time() + int(data.get('expires_in', 3600)),
    )


@app.before_request
def guard():
    if request.method in ('POST', 'PATCH', 'DELETE'):
        expected = session.get('csrf', '')
        supplied = (
            request.headers.get('X-CSRF-Token')
            or request.form.get('csrf', '')
        )

        if not expected or not secrets.compare_digest(expected, supplied):
            raise ApiError(
                'Form expired. Reload the page and try again.', 400
            )


@app.after_request
def privacy(response):
    response.headers.update({
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
    })
    return response


@app.errorhandler(ApiError)
def api_error(error):
    return jsonify(
        error=error.message,
        message=error.message,
        code=error.code,
        feature=error.feature,
        required=error.required,
        details=error.details,
    ), error.status


@app.errorhandler(requests.RequestException)
def network_error(error):
    message = 'Microsoft could not be reached. Please retry.'
    return jsonify(error=message, message=message), 502


# Scope hints describe the interface. Microsoft enforces authorization.
FEATURE_SCOPES = {
    'mail_read': ['Mail.Read', 'Mail.ReadWrite'],
    'mail_write': ['Mail.ReadWrite'],
    'mail_send': ['Mail.Send'],
    'rules_read': ['MailboxSettings.Read', 'MailboxSettings.ReadWrite'],
    'rules_write': ['MailboxSettings.ReadWrite'],
    'settings': ['MailboxSettings.ReadWrite'],
    'calendar': ['Calendars.ReadWrite'],
    'contacts': ['Contacts.ReadWrite'],
    'tasks': ['Tasks.ReadWrite'],
    'groups': ['GroupMember.Read.All', 'Directory.Read.All'],
}


def permission_for(path, method):
    if 'messageRules' in path:
        key = 'rules_read' if method == 'GET' else 'rules_write'
        return 'inbox rules', FEATURE_SCOPES[key]

    if 'mailboxSettings' in path:
        permission = (
            'MailboxSettings.Read'
            if method == 'GET'
            else 'MailboxSettings.ReadWrite'
        )
        return 'mailbox settings', [permission]

    if '/todo' in path:
        return 'Microsoft To Do', FEATURE_SCOPES['tasks']

    if '/memberOf' in path:
        return 'group memberships', FEATURE_SCOPES['groups']

    if any(value in path for value in ['/events', '/calendar']):
        permission = (
            'Calendars.Read' if method == 'GET' else 'Calendars.ReadWrite'
        )
        return 'calendar', [permission]

    if '/contacts' in path:
        permission = (
            'Contacts.Read' if method == 'GET' else 'Contacts.ReadWrite'
        )
        return 'contacts', [permission]

    if any(path.endswith(value) for value in (
        '/sendMail', '/send', '/reply', '/replyAll', '/forward'
    )):
        return 'sending mail', ['Mail.Send']

    if method == 'GET':
        return 'reading mail', ['Mail.Read', 'Mail.ReadWrite']

    return 'managing mail', ['Mail.ReadWrite']


def scope_hints(record):
    if record.get('scopes'):
        return [
            scope.removeprefix('https://graph.microsoft.com/')
            for scope in record['scopes'].split()
        ]

    try:
        raw = record['access'].split('.')[1]
        data = json.loads(
            base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
        )
        scopes = data.get('scp')
        return scopes.split() if isinstance(scopes, str) else None
    except (ValueError, IndexError, UnicodeDecodeError, TypeError):
        return None


@app.get('/api/session')
def session_info():
    record = account()
    scopes = scope_hints(record)

    record.setdefault('who', None)
    if not record['who']:
        record['who'] = 'Mail Console'
        try:
            profile = graph_request(
                'GET',
                '/me',
                {'$select': 'displayName,mail,userPrincipalName'},
            )
            record['who'] = (
                profile.get('mail')
                or profile.get('userPrincipalName')
                or profile.get('displayName')
                or 'Mail Console'
            )
        except ApiError:
            pass

    capabilities = {
        name: {
            'state': (
                'unknown'
                if scopes is None
                else (
                    'available'
                    if any(scope in scopes for scope in required)
                    else 'missing'
                )
            ),
            'required': required,
        }
        for name, required in FEATURE_SCOPES.items()
    }

    return {
        'capabilities': capabilities,
        'scopes': scopes,
        'oauth': bool(OAUTH_CLIENT),
        'refreshEnabled': bool(record['refresh']),
        'expiresAt': record['expires'],
        'clientId': record['cid'],
        'who': record.get('who', 'Mail Console'),
    }


SAFE_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | set(
    'p div span br hr h1 h2 h3 h4 h5 h6 table thead tbody tfoot '
    'tr td th colgroup col img font blockquote pre code ul ol li '
    'sup sub center strike s u caption'.split()
)

CSS = CSSSanitizer(allowed_css_properties=[
    'color', 'background-color', 'font-family', 'font-size',
    'font-weight', 'font-style', 'text-align', 'text-decoration',
    'line-height', 'padding', 'margin', 'border', 'border-collapse',
    'width', 'max-width', 'height', 'vertical-align', 'white-space',
])


def link_scheme(value):
    try:
        return urlsplit(value.strip()).scheme.lower()
    except ValueError:
        return ''


def safe_attribute(tag, name, value):
    if name == 'style':
        return True

    if tag == 'a':
        return name in ('href', 'title') and (
            name != 'href'
            or link_scheme(value) in ('http', 'https', 'mailto', 'tel')
        )

    if tag == 'img':
        return name in ('alt', 'width', 'height') or (
            name == 'src'
            and (
                link_scheme(value) in ('http', 'https')
                or bool(re.fullmatch(
                    r'data:image/(?:png|gif|jpeg|webp|bmp|avif);'
                    r'base64,[A-Za-z0-9+/=\s]+',
                    value,
                ))
            )
        )

    return name in (
        'title', 'align', 'valign', 'colspan', 'rowspan', 'width',
        'height', 'border', 'cellpadding', 'cellspacing',
        'color', 'face', 'size',
    )


def safe_link(attributes, new=False):
    href = attributes.get((None, 'href'), '').strip()

    if link_scheme(href) not in ('http', 'https', 'mailto', 'tel'):
        return None

    attributes[(None, 'target')] = '_blank'
    attributes[(None, 'rel')] = 'noopener noreferrer'
    return attributes


def safe_message_body(body, images=None):
    source = body.get('content') or ''

    if images:
        source = re.sub(
            r'''cid:([^\s<>"']+)''',
            lambda match: images.get(
                unquote(html.unescape(match.group(1)))
                .strip('<>').casefold(),
                match.group(0),
            ),
            source,
            flags=re.I,
        )

    if body.get('contentType', '').lower() != 'html':
        source = '<pre>' + html.escape(source) + '</pre>'

    source = re.sub(
        r'<(script|style|iframe|object|svg|math|form)\b[^>]*>'
        r'.*?</\1\s*>',
        '',
        source,
        flags=re.I | re.S,
    )

    cleaned = bleach.clean(
        source,
        tags=SAFE_TAGS,
        attributes=safe_attribute,
        protocols=['http', 'https', 'mailto', 'tel', 'data'],
        css_sanitizer=CSS,
        strip=True,
    )

    return bleach.linkifier.Linker(
        callbacks=[safe_link],
        skip_tags=['code'],
        parse_email=True,
    ).linkify(cleaned)


def embedded_message_images(path, body):
    source = body.get('content') or ''
    wanted = {
        unquote(html.unescape(cid)).strip('<>').casefold()
        for cid in re.findall(r"cid:([^\s<>\"']+)", source, flags=re.I)
    }

    if not wanted:
        return {}, False

    images = {}
    total = 0
    data = graph_request('GET', path + '/attachments', {'$top': 100})

    for page in range(20):
        for attachment in data.get('value', []):
            cid = (
                attachment.get('contentId') or ''
            ).strip('<>').casefold()

            if cid not in wanted:
                continue

            mime = (
                attachment.get('contentType') or ''
            ).split(';')[0].lower()

            if mime not in (
                'image/png', 'image/jpeg', 'image/gif',
                'image/webp', 'image/bmp', 'image/avif',
            ):
                continue

            encoded = attachment.get('contentBytes')

            if not encoded and attachment.get('id'):
                attachment_id = requests.utils.quote(
                    attachment['id'], safe=''
                )
                detail = graph_request(
                    'GET', path + '/attachments/' + attachment_id
                )
                encoded = detail.get('contentBytes')

            if (
                not isinstance(encoded, str)
                or len(encoded) > 16 * 1024 * 1024
                or total + len(encoded) > 32 * 1024 * 1024
            ):
                continue

            encoded = re.sub(r'\s+', '', encoded)

            try:
                base64.b64decode(encoded, validate=True)
            except ValueError:
                continue

            images[cid] = 'data:' + mime + ';base64,' + encoded
            total += len(encoded)

        if wanted.issubset(images) or not data.get('@odata.nextLink'):
            break

        link = urlsplit(data['@odata.nextLink'])

        if (
            link.scheme != 'https'
            or link.netloc != 'graph.microsoft.com'
            or not link.path.startswith('/v1.0' + path + '/attachments')
        ):
            break

        data = graph_request(
            'GET',
            link.path[len('/v1.0'):],
            dict(parse_qsl(link.query)),
        )

    return images, not wanted.issubset(images)


@app.get('/health')
def health():
    return {'status': 'ok'}


LOGIN_HTML = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail Console — Sign in</title>
<style>
body {
    font:14px 'Segoe UI',sans-serif;
    background:#faf9f8;
    color:#201f1e;
    margin:0;
}
main {
    max-width:440px;
    margin:8vh auto;
    padding:28px;
    background:#fff;
    border:1px solid #e1dfdd;
    border-radius:8px;
}
h1 { font-size:23px; }
label { display:block; margin:18px 0 6px; }
input,select,button {
    width:100%;
    box-sizing:border-box;
    font:inherit;
    padding:10px;
    border-radius:4px;
    border:1px solid #8a8886;
}
button {
    margin-top:22px;
    background:#0078d4;
    color:white;
    border:0;
    cursor:pointer;
}
#error { color:#a4262c; line-height:1.5; }
p { line-height:1.5; }
a { color:#0078d4; }
</style>
</head>
<body>
<main>
<h1>Mail Console</h1>
<p>Sign in with your existing Microsoft token.</p>

{% if oauth %}
<p><a href="/auth/microsoft">Sign in with Microsoft</a></p>
{% endif %}

<form id="signin">
    <label for="kind">Token type</label>
    <select id="kind">
        <option value="refresh">Refresh token</option>
        <option value="access">Access token</option>
    </select>

    <label for="token">Token</label>
    <input id="token" type="password" required autocomplete="off">

    <label for="client">Original client ID</label>
    <select id="client">
        {% for cid in client_ids %}
        <option>{{ cid }}</option>
        {% endfor %}
    </select>

    <button id="submit">Sign in</button>
    <p id="error" role="alert"></p>
</form>
</main>

<script>
const CSRF = {{ csrf|tojson }};

document.getElementById('kind').onchange = function() {
    document.getElementById('client').disabled = this.value === 'access';
};

document.getElementById('signin').onsubmit = async function(e) {
    e.preventDefault();

    const button = document.getElementById('submit');
    button.disabled = true;
    document.getElementById('error').textContent = '';

    try {
        const response = await fetch('/login', {
            method:'POST',
            headers:{
                'Content-Type':'application/json',
                'X-CSRF-Token':CSRF
            },
            body:JSON.stringify({
                kind:document.getElementById('kind').value,
                token:document.getElementById('token').value.trim(),
                client_id:document.getElementById('client').value
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw Error(data.message || data.error || 'Sign-in failed.');
        }

        document.getElementById('token').value = '';
        location.replace('/');
    } catch (error) {
        document.getElementById('error').textContent = error.message;
    } finally {
        button.disabled = false;
    }
};
</script>
</body>
</html>'''


def _template_vars():
    session.setdefault('csrf', secrets.token_urlsafe(32))
    connected = False

    try:
        account()
        connected = True
    except ApiError:
        pass

    return session['csrf'], connected, CLIENT_IDS, OAUTH_CLIENT


@app.get('/')
def home():
    csrf, connected, client_ids, oauth = _template_vars()

    if not connected:
        return render_template_string(
            LOGIN_HTML,
            csrf=csrf,
            client_ids=client_ids,
            oauth=bool(oauth),
        )

    path = os.path.join(os.path.dirname(__file__), 'index.html')

    try:
        with open(path, encoding='utf-8') as fp:
            template = fp.read()
    except FileNotFoundError:
        template = (
            '<!doctype html><meta charset="utf-8"><title>Mailbox</title>'
            '<h2>Mailbox viewer</h2><p>index.html not deployed.</p>'
            '<p>Connected: {{ connected }}</p>'
        )

    template = template.replace("'__CSRF__'", "{{ csrf|tojson }}")

    return render_template_string(
        template,
        csrf=csrf,
        connected=connected,
        client_ids=client_ids,
        oauth=bool(oauth),
    )


@app.post('/login')
def login():
    values = request.get_json(silent=True) or {}
    token = values.get('token', '').strip()
    cid = values.get('client_id', '')

    if not token:
        raise ApiError('Enter a token.')

    if values.get('kind') == 'access':
        probe = requests.get(
            GRAPH + '/me',
            params={'$select': 'id'},
            headers={'Authorization': 'Bearer ' + token},
            timeout=20,
        )

        if not probe.ok:
            raise ApiError(
                'That access token is expired or invalid for Microsoft Graph.',
                401,
            )

        data = {'access_token': token}
    else:
        if cid not in CLIENT_IDS:
            raise ApiError(
                'Select the client ID that issued your refresh token.'
            )

        data = token_request({
            'client_id': cid,
            'grant_type': 'refresh_token',
            'refresh_token': token,
            'scope': 'https://graph.microsoft.com/.default offline_access',
        })

    save_login(
        data,
        cid,
        token if values.get('kind') != 'access' else '',
    )
    return {'ok': True}


@app.post('/logout')
def logout():
    with STORE_LOCK:
        STORE.pop(session.get('sid'), None)

    session.clear()
    return {'ok': True}


@app.get('/auth/microsoft')
def microsoft_login():
    if not OAUTH_CLIENT:
        raise ApiError('Microsoft application registration is not configured.')

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)

    extra = {
        'tasks': 'Tasks.ReadWrite',
        'groups': 'GroupMember.Read.All',
        'shared': (
            'Mail.ReadWrite.Shared Mail.Send.Shared '
            'Calendars.ReadWrite.Shared Contacts.ReadWrite.Shared'
        ),
    }

    requested_scopes = SCOPES + ' ' + extra.get(
        request.args.get('feature'), ''
    )

    session.update(
        oauth_state=state,
        verifier=verifier,
        requested_scopes=requested_scopes,
    )

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip('=')

    return redirect(
        'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?'
        + urlencode({
            'client_id': OAUTH_CLIENT,
            'response_type': 'code',
            'redirect_uri': PUBLIC_URL + '/auth/callback',
            'scope': requested_scopes,
            'prompt': 'select_account',
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })
    )


@app.get('/auth/callback')
def callback():
    state = session.pop('oauth_state', '')
    verifier = session.pop('verifier', '')
    requested_scopes = session.pop('requested_scopes', SCOPES)

    if not state or not secrets.compare_digest(
        state, request.args.get('state', '')
    ):
        raise ApiError('Sign-in state expired. Start sign-in again.')

    if not request.args.get('code'):
        raise ApiError('Microsoft sign-in was cancelled or denied.', 401)

    values = {
        'client_id': OAUTH_CLIENT,
        'grant_type': 'authorization_code',
        'code': request.args['code'],
        'code_verifier': verifier,
        'redirect_uri': PUBLIC_URL + '/auth/callback',
        'scope': requested_scopes,
    }

    if OAUTH_SECRET:
        values['client_secret'] = OAUTH_SECRET

    data = token_request(values)
    save_login(data, OAUTH_CLIENT, managed=True)
    return redirect('/')


RESOURCE = re.compile(
    r'^/(?:me|users/[^/]+)'
    r'(?:/(?:mailFolders|messages|sendMail|mailboxSettings|outlook|events|'
    r'calendarView|calendars|calendar|contacts|contactFolders|people|todo|'
    r'memberOf|findMeetingTimes|getSchedule)(?:/.*)?)?$'
)


def valid_path(path):
    if (
        not isinstance(path, str)
        or not RESOURCE.fullmatch(path)
        or '..' in path
        or '?' in path
        or '#' in path
        or '\\' in path
    ):
        raise ApiError('This Microsoft Graph resource is not enabled.')

    return path


def graph_request(method, path, query=None, payload=None, binary=False):
    valid_path(path)
    record = account()

    with record['lock']:
        if record['refresh'] and time.time() >= record['expires'] - 90:
            renew(record)

        for attempt in range(2):
            response = requests.request(
                method,
                GRAPH + path,
                params=query or {},
                json=payload,
                headers={
                    'Authorization': 'Bearer ' + record['access'],
                    'Prefer': 'outlook.body-content-type="html"',
                },
                timeout=25,
            )

            if response.status_code == 401 and attempt == 0:
                renew(record)
                continue

            if not response.ok:
                try:
                    details = response.json().get('error', {})
                    message = details.get(
                        'message', 'Microsoft rejected this operation.'
                    )
                    code = details.get('code', 'GraphError')
                except ValueError:
                    message = 'Microsoft rejected this operation.'
                    code = 'GraphError'
                    details = {}

                if response.status_code == 403:
                    feature, required = permission_for(path, method)

                    error = ApiError(
                        'Microsoft denied the ' + feature + ' request. '
                        + message,
                        403,
                    )
                    error.code = 'permission_required'
                    error.feature = feature
                    error.required = required

                    inner = (
                        details.get('innerError', {})
                        if isinstance(details, dict) else {}
                    )
                    headers = (
                        response.headers
                        if isinstance(response.headers, dict)
                        or hasattr(response.headers, 'items')
                        else {}
                    )
                    request_id = headers.get('request-id') or (
                        inner.get('request-id')
                        if isinstance(inner, dict) else None
                    )

                    error.details = {
                        'graphCode': code,
                        'method': method,
                        'path': path,
                        'requestId': (
                            request_id
                            if isinstance(request_id, str) else None
                        ),
                        'scopeHint': scope_hints(record),
                    }
                    raise error

                raise ApiError(
                    code + ': ' + message, response.status_code
                )

            if binary:
                return response.content, response.headers.get(
                    'Content-Type', 'application/octet-stream'
                )

            if not response.content:
                return {}

            try:
                data = response.json()

                if isinstance(data, dict) and isinstance(
                    data.get('body'), dict
                ):
                    images = {}

                    if method == 'GET' and re.fullmatch(
                        r'/(?:me|users/[^/]+)/messages/[^/]+', path
                    ):
                        try:
                            images, missing = embedded_message_images(
                                path, data['body']
                            )

                            if missing:
                                data['imageNotice'] = (
                                    'Some embedded images were unavailable '
                                    'or use an unsupported image format.'
                                )
                        except (ApiError, requests.RequestException):
                            data['imageNotice'] = (
                                'Some embedded pictures could not be retrieved. '
                                'You can still read this message.'
                            )

                    data['safeBody'] = safe_message_body(
                        data['body'], images
                    )

                return data
            except ValueError:
                raise ApiError(
                    'Microsoft returned an unexpected response.', 502
                )


@app.post('/api/graph')
def graph_api():
    body = request.get_json(silent=True) or {}
    method = body.get('method', 'GET').upper()

    if method not in ('GET', 'POST', 'PATCH', 'DELETE'):
        raise ApiError('Unsupported request method.')

    return jsonify(graph_request(
        method,
        body.get('path', ''),
        body.get('query'),
        body.get('payload'),
    ))


@app.post('/api/download')
def download():
    body = request.get_json(silent=True) or {}
    path = body.get('path', '')

    if not re.fullmatch(
        r'/(?:me|users/[^/]+)/messages/[^/]+'
        r'(?:/attachments/[^/]+)?/\$value',
        path,
    ):
        raise ApiError('Invalid download path.')

    content, content_type = graph_request('GET', path, binary=True)

    name = re.sub(
        r'[^a-zA-Z0-9._ -]', '_', body.get('name', 'download')
    )[:120]

    response = app.response_class(content, content_type=content_type)
    response.headers['Content-Disposition'] = (
        'attachment; filename="' + name + '"'
    )
    return response


@app.get('/source.zip')
def source_zip():
    if os.getenv('ENABLE_SOURCE_DOWNLOAD') != '1':
        raise ApiError(
            'Source download is available only in the development preview.',
            404,
        )

    import io
    import zipfile

    buffer = io.BytesIO()
    root = os.path.dirname(__file__)

    with zipfile.ZipFile(
        buffer, 'w', zipfile.ZIP_DEFLATED
    ) as archive:
        for name in [
            'mailbox.py', 'index.html', 'requirements.txt',
            'README.txt', 'FEATURES.txt',
        ]:
            with open(os.path.join(root, name), 'rb') as fp:
                archive.writestr('outlook-mailbox/' + name, fp.read())

    response = app.response_class(
        buffer.getvalue(), content_type='application/zip'
    )
    response.headers['Content-Disposition'] = (
        'attachment; filename="outlook-mailbox.zip"'
    )
    return response


# Routes and response formats expected by index.html.

def _ui_json():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        raise ApiError('Send a JSON object with this request.')

    return data


def _ui_number(name, default, maximum):
    try:
        value = int(request.args.get(name, default))
    except (ValueError, TypeError):
        raise ApiError('Invalid ' + name + ' value.')

    return max(0, min(value, maximum))


def _ui_collection(path, query=None):
    result = graph_request('GET', path, query)
    rows = list(result.get('value', []))

    for _ in range(100):
        next_link = result.get('@odata.nextLink')

        if not next_link:
            return rows

        link = urlsplit(next_link)

        if (
            link.scheme != 'https'
            or link.netloc != 'graph.microsoft.com'
            or link.path != '/v1.0' + path
        ):
            raise ApiError(
                'Microsoft returned an unexpected pagination URL.', 502
            )

        result = graph_request(
            'GET', path, dict(parse_qsl(link.query))
        )
        rows.extend(result.get('value', []))

    raise ApiError('Too many pages returned. Narrow the request.', 400)


@app.get('/api/folders')
def ui_folders():
    folders = _ui_collection('/me/mailFolders', {
        '$top': 100,
        '$select': (
            'id,displayName,parentFolderId,totalItemCount,'
            'unreadItemCount,childFolderCount'
        ),
    })
    return jsonify(folders=folders)


@app.get('/api/messages')
def ui_messages():
    folder = request.args.get('folder', 'inbox').strip() or 'inbox'
    path = (
        '/me/mailFolders/'
        + requests.utils.quote(folder, safe='')
        + '/messages'
    )

    query = {
        '$top': max(1, _ui_number('top', 20, 50)),
        '$skip': _ui_number('skip', 0, 1000000),
        '$select': (
            'id,subject,from,receivedDateTime,isRead,hasAttachments,'
            'bodyPreview,importance'
        ),
    }

    search = request.args.get('search', '').strip()

    if search:
        query['$search'] = (
            '"' + search.replace('\\', '').replace('"', '') + '"'
        )
    else:
        query['$orderby'] = 'receivedDateTime desc'

    data = graph_request('GET', path, query)

    return jsonify(
        messages=data.get('value', []),
        cursor=data.get('@odata.nextLink'),
    )


@app.get('/api/messages/<path:mid>')
def ui_message(mid):
    path = '/me/messages/' + requests.utils.quote(mid, safe='')
    message = graph_request('GET', path)

    message['safeHtml'] = (
        message.get('safeBody')
        or safe_message_body(message.get('body', {}))
    )

    return jsonify(message)


@app.delete('/api/messages/<path:mid>')
def ui_delete_message(mid):
    graph_request(
        'DELETE', '/me/messages/' + requests.utils.quote(mid, safe='')
    )
    return jsonify(ok=True)


@app.post('/api/messages/<path:mid>/read')
def ui_mark_read(mid):
    data = _ui_json()
    is_read = data.get('isRead', True)

    if not isinstance(is_read, bool):
        raise ApiError('isRead must be true or false.')

    graph_request(
        'PATCH',
        '/me/messages/' + requests.utils.quote(mid, safe=''),
        payload={'isRead': is_read},
    )

    return jsonify(ok=True)


@app.post('/api/messages/<path:mid>/move')
def ui_move_message(mid):
    data = _ui_json()
    destination = str(data.get('destinationId') or '').strip()

    if not destination:
        raise ApiError('Choose a destination folder.')

    moved = graph_request(
        'POST',
        '/me/messages/' + requests.utils.quote(mid, safe='') + '/move',
        payload={'destinationId': destination},
    )

    return jsonify(moved)


def _ui_addresses(value):
    return [
        {'emailAddress': {'address': address.strip()}}
        for address in re.split(r'[,;]', str(value or ''))
        if address.strip()
    ]


@app.post('/api/send')
def ui_send():
    data = _ui_json()
    recipients = _ui_addresses(data.get('to'))

    if not recipients:
        raise ApiError('Enter at least one recipient.')

    graph_request('POST', '/me/sendMail', payload={
        'message': {
            'subject': str(data.get('subject') or ''),
            'body': {
                'contentType': 'HTML',
                'content': str(data.get('body') or ''),
            },
            'toRecipients': recipients,
        },
        'saveToSentItems': True,
    })

    return jsonify(ok=True)


@app.get('/api/rules')
def ui_rules():
    rules = _ui_collection('/me/mailFolders/inbox/messageRules')
    rules.sort(key=lambda rule: rule.get('sequence', 0))
    return jsonify(rules=rules)


def _ui_rule_payload(data, previous=None):
    previous = previous or {}

    name = str(
        data.get('displayName', previous.get('displayName', '')) or ''
    ).strip()

    if not name:
        raise ApiError('Enter a rule name.')

    conditions = dict(previous.get('conditions') or {})
    actions = dict(previous.get('actions') or {})

    for input_name, graph_name in [
        ('fromContains', 'senderContains'),
        ('subjectContains', 'subjectContains'),
    ]:
        if input_name in data:
            terms = [
                term.strip()
                for term in str(data[input_name] or '').split(',')
                if term.strip()
            ]

            conditions.pop(graph_name, None)

            if terms:
                conditions[graph_name] = terms

    if 'moveTo' in data:
        actions.pop('moveToFolder', None)

        if data['moveTo']:
            actions['moveToFolder'] = str(data['moveTo'])

    for input_name, graph_name in [
        ('delete', 'delete'),
        ('markRead', 'markAsRead'),
    ]:
        if input_name in data:
            if not isinstance(data[input_name], bool):
                raise ApiError(input_name + ' must be true or false.')

            actions.pop(graph_name, None)

            if data[input_name]:
                actions[graph_name] = True

    if actions.get('delete') and actions.get('moveToFolder'):
        raise ApiError('Choose either moving or deleting, not both.')

    if not any(
        value for key, value in actions.items()
        if key != 'stopProcessingRules'
    ):
        raise ApiError('Choose at least one rule action.')

    payload = {
        'displayName': name,
        'conditions': conditions,
        'actions': actions,
    }

    if not previous:
        payload.update(sequence=1, isEnabled=True)

    return payload


@app.post('/api/rules')
def ui_create_rule():
    payload = _ui_rule_payload(_ui_json())

    return jsonify(graph_request(
        'POST',
        '/me/mailFolders/inbox/messageRules',
        payload=payload,
    ))


@app.patch('/api/rules/<path:rid>')
def ui_update_rule(rid):
    path = (
        '/me/mailFolders/inbox/messageRules/'
        + requests.utils.quote(rid, safe='')
    )

    data = _ui_json()
    previous = graph_request('GET', path)
    payload = _ui_rule_payload(data, previous)

    return jsonify(graph_request('PATCH', path, payload=payload))


@app.delete('/api/rules/<path:rid>')
def ui_delete_rule(rid):
    graph_request(
        'DELETE',
        '/me/mailFolders/inbox/messageRules/'
        + requests.utils.quote(rid, safe=''),
    )
    return jsonify(ok=True)


@app.post('/api/logout')
def ui_logout():
    return logout()


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', '10000')),
    )
```
