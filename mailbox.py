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
app.logger.setLevel('INFO')
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=bool(os.getenv('RENDER')),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)

GRAPH = 'https://graph.microsoft.com/v1.0'
TOKEN_EP = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

WRITE_SCOPES = (
    'https://graph.microsoft.com/Mail.ReadWrite '
    'https://graph.microsoft.com/Mail.Send '
    'https://graph.microsoft.com/MailboxSettings.ReadWrite '
    'https://graph.microsoft.com/User.Read '
    'offline_access'
)

CLIENT_IDS = [
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  
    "1b730954-1685-4b74-9bfd-dac224a7b894", 
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

    app.logger.info(
        'TOKEN_EXCHANGE_OK client_id=%s',
        values.get('client_id', ''),
    )
    return data


def _token_claims(token):
    """Decode diagnostic hints only. Microsoft validates authorization."""
    try:
        middle = token.split('.')[1]
        claims = json.loads(
            base64.urlsafe_b64decode(
                middle + '=' * (-len(middle) % 4)
            )
        )
        return claims if isinstance(claims, dict) else {}
    except (ValueError, IndexError, TypeError, AttributeError):
        return {}


def _log_token_scope(record, event):
    claims = _token_claims(record.get('access', ''))
    scopes = claims.get('scp') or claims.get('scope')
    source = 'access_token_jwt'

    if not scopes:
        scopes = record.get('granted_scp')
        source = 'token_response_scp' if scopes else 'unavailable'

    if isinstance(scopes, list):
        scopes = ' '.join(str(item) for item in scopes)

    scopes = re.sub(
        r'[^A-Za-z0-9_./: -]',
        '',
        str(scopes or 'unavailable'),
    )[:3000]

    app.logger.info(
        'GRAPH_GRANTED_SCOPE event=%s client_id=%s source=%s scp=%s',
        event,
        record.get('cid', ''),
        source,
        scopes,
    )


def upgrade_token(refresh_token, client_id, tenant_id=None):
    endpoints = []

    if isinstance(tenant_id, str) and re.fullmatch(
        r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}',
        tenant_id,
    ):
        endpoints.append((
            'tenant',
            'https://login.microsoftonline.com/'
            + tenant_id
            + '/oauth2/v2.0/token',
        ))

    endpoints.append(('common', TOKEN_EP))

    for label, endpoint in endpoints:
        app.logger.info(
            'TOKEN_ENDPOINT_ATTEMPT endpoint=%s client_id=%s tid_source=%s',
            label,
            client_id,
            (
                'access_token.tid'
                if label == 'tenant'
                else 'common_fallback_or_no_tid'
            ),
        )

        try:
            response = requests.post(
                endpoint,
                data={
                    'client_id': client_id,
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'scope': WRITE_SCOPES,
                },
                timeout=20,
            )
        except requests.RequestException:
            app.logger.info(
                'TOKEN_UPGRADE_FAILED endpoint=%s client_id=%s '
                'status=network_error',
                label,
                client_id,
            )
            continue

        app.logger.info(
            'TOKEN_ENDPOINT_RESULT endpoint=%s client_id=%s status=%s',
            label,
            client_id,
            response.status_code,
        )

        try:
            data = response.json()
        except ValueError:
            data = {}

        if (
            response.ok
            and isinstance(data, dict)
            and data.get('access_token')
        ):
            app.logger.info(
                'TOKEN_UPGRADE_EXCHANGE_OK endpoint=%s client_id=%s',
                label,
                client_id,
            )
            return data

        text = response.text.replace(
            refresh_token, '[REDACTED]'
        )
        text = re.sub(
            r'("(?:access_token|refresh_token|id_token|client_secret)"'
            r'\s*:\s*")[^"]*',
            r'\1[REDACTED]',
            text,
            flags=re.I,
        )
        text = re.sub(
            r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            '[REDACTED_JWT]',
            text,
        )
        text = text.replace('\r', ' ').replace('\n', ' ')[:300]

        app.logger.info(
            'TOKEN_UPGRADE_FAILED endpoint=%s client_id=%s '
            'status=%s body=%s',
            label,
            client_id,
            response.status_code,
            text,
        )

    return None


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
            'granted_scp': data.get('scp'),
            'used': now,
            'expires': now + int(data.get('expires_in', 3600)),
            'lock': threading.RLock(),
        }


def account():
    with STORE_LOCK:
        sid = session.get('sid')
        record = STORE.get(sid)

        if not record or time.time() - record['used'] > 7200:
            STORE.pop(sid, None)
            raise ApiError(
                'Your session expired. Sign in again.', 401
            )

        record['used'] = time.time()

        should_attempt = (
            bool(record.get('refresh'))
            and not record.get('write_upgrade_attempted')
            and not request.environ.get(
                'mailbox.write_upgrade_attempted'
            )
        )

    if should_attempt:
        request.environ['mailbox.write_upgrade_attempted'] = True

        # Nested lock order: record['lock'] -> STORE_LOCK; never acquire the record lock while holding STORE_LOCK.
        with record['lock']:
            with STORE_LOCK:
                if STORE.get(sid) is not record:
                    raise ApiError(
                        'Your session expired. Sign in again.', 401
                    )

                should_attempt = (
                    bool(record.get('refresh'))
                    and not record.get('write_upgrade_attempted')
                )

                if should_attempt:
                    refresh = record['refresh']
                    client_id = record['cid']
                    tenant_id = _token_claims(
                        record.get('access', '')
                    ).get('tid')

            if should_attempt:
                updates = None

                try:
                    upgraded = upgrade_token(
                        refresh, client_id, tenant_id
                    )

                    if upgraded:
                        updates = {
                            'access': upgraded['access_token'],
                            'refresh': (
                                upgraded.get('refresh_token') or refresh
                            ),
                            'expires': (
                                time.time()
                                + int(upgraded.get('expires_in', 3600))
                            ),
                            'scopes': (
                                upgraded.get('scope')
                                or record.get('scopes')
                            ),
                            'granted_scp': upgraded.get('scp'),
                            'write_ok': True,
                            'write_upgrade_attempted': True,
                        }
                except Exception:
                    app.logger.info(
                        'TOKEN_UPGRADE_SKIPPED client_id=%s '
                        'reason=exchange_error',
                        client_id,
                    )

                with STORE_LOCK:
                    if STORE.get(sid) is record:
                        if updates is not None:
                            record.update(updates)
                        else:
                            record['write_upgrade_attempted'] = False
                            record['write_ok'] = False

    with STORE_LOCK:
        if STORE.get(sid) is not record:
            raise ApiError(
                'Your session expired. Sign in again.', 401
            )
        snapshot = dict(record)

    _log_token_scope(snapshot, 'account')
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
        values['scope'] = (
            'https://graph.microsoft.com/.default offline_access'
        )

    data = token_request(values)

    record.update(
        access=data['access_token'],
        refresh=data.get('refresh_token') or record['refresh'],
        scopes=data.get('scope') or record.get('scopes'),
        granted_scp=data.get('scp'),
        expires=time.time() + int(data.get('expires_in', 3600)),
    )
    _log_token_scope(record, 'renew')


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
            or link.path != '/v1.0' + path + '/attachments'
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
        return app.response_class(
            'index.html is missing. Deploy it beside mailbox.py.',
            status=500,
            mimetype='text/plain',
        )

    csrf_json = (
        json.dumps(csrf)
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('&', '\\u0026')
    )
    template = template.replace("'__CSRF__'", csrf_json)

    return app.response_class(
        template,
        mimetype='text/html',
    )


def _redacted_log_body(text, *credentials):
    text = str(text or '')

    for credential in credentials:
        if isinstance(credential, str) and credential:
            text = text.replace(credential, '[REDACTED]')

    text = re.sub(
        r'("(?:access_token|refresh_token|id_token|client_secret)"'
        r'\s*:\s*")[^"]*',
        r'\1[REDACTED]',
        text,
        flags=re.I,
    )
    text = re.sub(
        r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        '[REDACTED_JWT]',
        text,
    )

    return text.replace('\r', ' ').replace('\n', ' ')[:300]


@app.post('/login')
def login():
    values = request.get_json(silent=True)

    if not isinstance(values, dict):
        _log_token_scope(
            {'access': '', 'cid': ''},
            'login_attempt',
        )
        raise ApiError('Send a JSON object with this request.')

    token = str(values.get('token') or '').strip()
    selected_cid = str(values.get('client_id') or '')
    kind = values.get('kind')
    claims = _token_claims(token) if kind == 'access' else {}

    if kind == 'access':
        cid = (
            claims.get('azp')
            or claims.get('appid')
            or selected_cid
        )
    else:
        cid = selected_cid

    _log_token_scope(
        {
            'access': token if kind == 'access' else '',
            'cid': cid,
        },
        'login_attempt',
    )

    if not token:
        raise ApiError('Enter a token.')

    profile = None

    if kind == 'access':
        endpoint = GRAPH + '/me'

        try:
            probe = requests.get(
                endpoint,
                params={
                    '$select': 'displayName,mail,userPrincipalName'
                },
                headers={'Authorization': 'Bearer ' + token},
                timeout=5,
            )
        except requests.RequestException:
            app.logger.info(
                'LOGIN_PROBE_RESULT endpoint=%s client_id=%s '
                'status=network_error body=unavailable',
                endpoint,
                cid,
            )
            raise ApiError(
                'Microsoft could not be reached to validate this token. '
                'Please retry.',
                502,
            )

        if probe.status_code != 200:
            app.logger.info(
                'LOGIN_PROBE_RESULT endpoint=%s client_id=%s '
                'status=%s body=%s',
                endpoint,
                cid,
                probe.status_code,
                _redacted_log_body(probe.text, token),
            )

            if probe.status_code == 401:
                raise ApiError('Token rejected by Microsoft.', 401)

            if probe.status_code == 403:
                return jsonify(
                    ok=False,
                    code='under_scoped',
                    message=(
                        'Token is valid but Microsoft refused /me (403). '
                        'It likely lacks User.Read or the tenant restricts it. '
                        'Use a refresh token instead.'
                    ),
                ), 403

            status = (
                probe.status_code
                if 400 <= probe.status_code < 500
                else 502
            )

            raise ApiError(
                'Microsoft /me validation failed (HTTP '
                + str(probe.status_code)
                + ').',
                status,
            )

        app.logger.info(
            'LOGIN_PROBE_RESULT endpoint=%s client_id=%s status=200',
            endpoint,
            cid,
        )

        try:
            profile = probe.json()
        except ValueError:
            raise ApiError(
                'Microsoft returned unreadable profile data.', 502
            )

        if not isinstance(profile, dict):
            raise ApiError(
                'Microsoft returned unexpected profile data.', 502
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
            'scope': (
                'https://graph.microsoft.com/.default offline_access'
            ),
        })

    _log_token_scope(
        {
            'access': data['access_token'],
            'cid': cid,
            'granted_scp': data.get('scp'),
        },
        'login_accepted',
    )

    save_login(
        data,
        cid,
        token if kind != 'access' else '',
    )

    if profile:
        with STORE_LOCK:
            record = STORE.get(session.get('sid'))

            if record:
                record['who'] = (
                    profile.get('mail')
                    or profile.get('userPrincipalName')
                    or profile.get('displayName')
                    or 'Mail Console'
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
        raise ApiError(
            'Microsoft application registration is not configured.'
        )

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
        raise ApiError(
            'Microsoft sign-in was cancelled or denied.', 401
        )

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
        raise ApiError(
            'This Microsoft Graph resource is not enabled.'
        )

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
                        'Microsoft denied the '
                        + feature
                        + ' request. '
                        + message,
                        403,
                    )
                    error.code = 'permission_required'
                    error.feature = feature
                    error.required = required

                    inner = (
                        details.get('innerError', {})
                        if isinstance(details, dict)
                        else {}
                    )
                    headers = (
                        response.headers
                        if isinstance(response.headers, dict)
                        or hasattr(response.headers, 'items')
                        else {}
                    )
                    request_id = headers.get('request-id') or (
                        inner.get('request-id')
                        if isinstance(inner, dict)
                        else None
                    )

                    error.details = {
                        'graphCode': code,
                        'method': method,
                        'path': path,
                        'requestId': (
                            request_id
                            if isinstance(request_id, str)
                            else None
                        ),
                        'scopeHint': scope_hints(record),
                    }
                    raise error

                raise ApiError(
                    code + ': ' + message,
                    response.status_code,
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

    content, content_type = graph_request(
        'GET', path, binary=True
    )

    name = re.sub(
        r'[^a-zA-Z0-9._ -]',
        '_',
        body.get('name', 'download'),
    )[:120]

    response = app.response_class(
        content,
        content_type=content_type,
    )
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
                archive.writestr(
                    'outlook-mailbox/' + name,
                    fp.read(),
                )

    response = app.response_class(
        buffer.getvalue(),
        content_type='application/zip',
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
                'Microsoft returned an unexpected pagination URL.',
                502,
            )

        result = graph_request(
            'GET',
            path,
            dict(parse_qsl(link.query)),
        )
        rows.extend(result.get('value', []))

    raise ApiError(
        'Too many pages returned. Narrow the request.', 400
    )


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
    path = (
        '/me/messages/'
        + requests.utils.quote(mid, safe='')
    )
    message = graph_request('GET', path)

    message['safeHtml'] = (
        message.get('safeBody')
        or safe_message_body(message.get('body', {}))
    )

    return jsonify(message)


@app.delete('/api/messages/<path:mid>')
def ui_delete_message(mid):
    graph_request(
        'DELETE',
        '/me/messages/' + requests.utils.quote(mid, safe=''),
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
    destination = str(
        data.get('destinationId') or ''
    ).strip()

    if not destination:
        raise ApiError('Choose a destination folder.')

    moved = graph_request(
        'POST',
        '/me/messages/'
        + requests.utils.quote(mid, safe='')
        + '/move',
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
    rules = _ui_collection(
        '/me/mailFolders/inbox/messageRules'
    )
    rules.sort(
        key=lambda rule: rule.get('sequence', 0)
    )
    return jsonify(rules=rules)


def _ui_rule_payload(data, previous=None):
    previous = previous or {}

    name = str(
        data.get(
            'displayName',
            previous.get('displayName', ''),
        ) or ''
    ).strip()

    if not name:
        raise ApiError('Enter a rule name.')

    conditions = dict(
        previous.get('conditions') or {}
    )
    actions = dict(
        previous.get('actions') or {}
    )

    for input_name, graph_name in [
        ('fromContains', 'senderContains'),
        ('subjectContains', 'subjectContains'),
    ]:
        if input_name in data:
            terms = [
                term.strip()
                for term in str(
                    data[input_name] or ''
                ).split(',')
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
            if not isinstance(
                data[input_name], bool
            ):
                raise ApiError(
                    input_name + ' must be true or false.'
                )

            actions.pop(graph_name, None)

            if data[input_name]:
                actions[graph_name] = True

    if (
        actions.get('delete')
        and actions.get('moveToFolder')
    ):
        raise ApiError(
            'Choose either moving or deleting, not both.'
        )

    if not any(
        value
        for key, value in actions.items()
        if key != 'stopProcessingRules'
    ):
        raise ApiError(
            'Choose at least one rule action.'
        )

    payload = {
        'displayName': name,
        'conditions': conditions,
        'actions': actions,
    }

    if not previous:
        payload.update(
            sequence=1,
            isEnabled=True,
        )

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

    return jsonify(graph_request(
        'PATCH', path, payload=payload
    ))


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
