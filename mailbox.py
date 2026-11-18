import base64
import hashlib
import html
import io
import json
import os
import re
import secrets
import threading
import time
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import bleach
import requests
from bleach.css_sanitizer import CSSSanitizer
from flask import Flask, jsonify, redirect, render_template_string, request, session
from itsdangerous import BadSignature, URLSafeTimedSerializer


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)

ROOT = Path(__file__).resolve().parent
GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com/common/oauth2/v2.0"
TOKEN_ENDPOINT = LOGIN_BASE + "/token"
PUBLIC_URL = os.getenv(
    "PUBLIC_URL", "https://outlook-mailbox-viewer.onrender.com"
).rstrip("/")
OAUTH_CLIENT = os.getenv("MICROSOFT_CLIENT_ID", "")
OAUTH_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")

CLIENT_IDS = [
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1b730954-1685-4b74-9bfd-dac224a7b894",
]
SCOPES = (
    "offline_access User.Read Mail.ReadWrite Mail.Send "
    "Calendars.ReadWrite Contacts.ReadWrite MailboxSettings.ReadWrite"
)
REFRESH_SCOPES = "https://graph.microsoft.com/.default offline_access"
WRITE_SCOPES = (
    "https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send "
    "https://graph.microsoft.com/MailboxSettings.ReadWrite "
    "https://graph.microsoft.com/User.Read offline_access"
)
PROFILE_FIELDS = "displayName,mail,userPrincipalName"

STORE = {}
STORE_LOCK = threading.RLock()
SESSION_IDLE_LIMIT = 7200

FEATURE_SCOPES = {
    "mail_read": ["Mail.Read", "Mail.ReadWrite"],
    "mail_write": ["Mail.ReadWrite"],
    "mail_send": ["Mail.Send"],
    "rules_read": ["MailboxSettings.Read", "MailboxSettings.ReadWrite"],
    "rules_write": ["MailboxSettings.ReadWrite"],
    "settings": ["MailboxSettings.ReadWrite"],
    "calendar": ["Calendars.ReadWrite"],
    "contacts": ["Contacts.ReadWrite"],
    "tasks": ["Tasks.ReadWrite"],
    "groups": ["GroupMember.Read.All", "Directory.Read.All"],
}

GRAPH_RESOURCE = re.compile(
    r"^/(?:me|users/[^/]+)"
    r"(?:/(?:mailFolders|messages|sendMail|mailboxSettings|outlook|events|"
    r"calendarView|calendars|calendar|contacts|contactFolders|people|todo|"
    r"memberOf|findMeetingTimes|getSchedule)(?:/.*)?)?$"
)
MESSAGE_RESOURCE = re.compile(r"/(?:me|users/[^/]+)/messages/[^/]+")
DOWNLOAD_RESOURCE = re.compile(
    r"/(?:me|users/[^/]+)/messages/[^/]+(?:/attachments/[^/]+)?/\$value"
)
MAIL_RULES = "/me/mailFolders/inbox/messageRules"
CURSORS = URLSafeTimedSerializer(app.secret_key, salt="mail-page")


class ApiError(Exception):
    def __init__(
        self, message, status=400, *, code="request_failed",
        feature=None, required=None, details=None
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.feature = feature
        self.required = required or []
        self.details = details or {}


@app.errorhandler(ApiError)
def api_error(error):
    message = str(error)
    return jsonify(
        ok=False,
        error=message,
        message=message,
        code=error.code,
        feature=error.feature,
        required=error.required,
        details=error.details,
    ), error.status


@app.errorhandler(requests.RequestException)
def network_error(error):
    message = "Microsoft could not be reached. Please retry."
    return jsonify(ok=False, error=message, message=message), 502


@app.before_request
def check_csrf():
    if request.method not in {"POST", "PATCH", "DELETE"}:
        return

    expected = session.get("csrf", "")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        raise ApiError("Form expired. Reload the page and try again.")


@app.after_request
def privacy_headers(response):
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
    })
    return response


def json_object():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ApiError("Send a JSON object with this request.")
    return value


def bounded_number(name, default, maximum):
    try:
        number = int(request.args.get(name, default))
    except (TypeError, ValueError):
        raise ApiError(f"Invalid {name} value.") from None
    return max(0, min(number, maximum))


def response_object(response):
    try:
        result = response.json()
    except ValueError:
        return {}
    return result if isinstance(result, dict) else {}


def token_request(values, endpoint=TOKEN_ENDPOINT):
    response = requests.post(endpoint, data=values, timeout=20)
    result = response_object(response)

    if not response.ok:
        code = str(result.get("error") or "invalid_token")
        raise ApiError(
            f"Microsoft sign-in failed ({code}). Check the token, "
            "its original client ID, or your tenant policy.",
            401,
        )

    if not result.get("access_token"):
        raise ApiError("Microsoft did not return an access token.", 502)

    return result


def token_claims(token):
    """Read diagnostic hints. Microsoft validates the token."""
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (AttributeError, IndexError, TypeError, ValueError):
        return {}
    return claims if isinstance(claims, dict) else {}


def scope_hints(record):
    raw = (
        record.get("scopes")
        or record.get("granted_scp")
        or token_claims(record["access"]).get("scp")
    )
    if not isinstance(raw, str):
        return None
    return [
        scope.removeprefix("https://graph.microsoft.com/")
        for scope in raw.split()
    ]


def expiry(data):
    try:
        return time.time() + int(data.get("expires_in", 3600))
    except (TypeError, ValueError):
        return time.time() + 3600


def profile_name(profile):
    return (
        profile.get("mail")
        or profile.get("userPrincipalName")
        or profile.get("displayName")
        or "Mail Console"
    )


def save_login(data, client_id, refresh="", managed=False, profile=None):
    now = time.time()
    with STORE_LOCK:
        for sid, record in list(STORE.items()):
            if now - record["used"] > SESSION_IDLE_LIMIT:
                STORE.pop(sid, None)

        STORE.pop(session.get("sid"), None)
        session.clear()
        sid = secrets.token_urlsafe(32)
        session.update(sid=sid, csrf=secrets.token_urlsafe(32))
        STORE[sid] = {
            "access": data["access_token"],
            "refresh": data.get("refresh_token") or refresh,
            "cid": client_id,
            "managed": managed,
            "scopes": data.get("scope"),
            "granted_scp": data.get("scp"),
            "who": profile_name(profile) if profile else None,
            "used": now,
            "expires": expiry(data),
            "lock": threading.RLock(),
            "write_upgrade_attempted": False,
        }


def account():
    with STORE_LOCK:
        sid = session.get("sid")
        record = STORE.get(sid)
        if not record or time.time() - record["used"] > SESSION_IDLE_LIMIT:
            STORE.pop(sid, None)
            raise ApiError("Your session expired. Sign in again.", 401)
        record["used"] = time.time()
    return record


def update_tokens(record, result):
    record.update(
        access=result["access_token"],
        refresh=result.get("refresh_token") or record["refresh"],
        scopes=result.get("scope") or record.get("scopes"),
        granted_scp=result.get("scp"),
        expires=expiry(result),
    )


def renew(record):
    if not record["refresh"]:
        raise ApiError("Access token expired. Sign in again with a fresh token.", 401)

    values = {
        "client_id": record["cid"],
        "grant_type": "refresh_token",
        "refresh_token": record["refresh"],
        "scope": (record.get("scopes") or SCOPES) if record["managed"] else REFRESH_SCOPES,
    }
    if record["managed"] and OAUTH_SECRET:
        values["client_secret"] = OAUTH_SECRET
    update_tokens(record, token_request(values))


def upgrade_token_if_needed(record):
    if (
        not record["refresh"]
        or record["managed"]
        or record["write_upgrade_attempted"]
        or request.environ.get("mailbox.write_upgrade_attempted")
    ):
        return

    request.environ["mailbox.write_upgrade_attempted"] = True
    granted = set(scope_hints(record) or [])
    if {"Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite"} <= granted:
        record["write_upgrade_attempted"] = True
        return

    tenant = token_claims(record["access"]).get("tid")
    endpoints = [TOKEN_ENDPOINT]
    if isinstance(tenant, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", tenant
    ):
        endpoints.insert(
            0, f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )

    values = {
        "client_id": record["cid"],
        "grant_type": "refresh_token",
        "refresh_token": record["refresh"],
        "scope": WRITE_SCOPES,
    }
    for endpoint in endpoints:
        try:
            result = token_request(values, endpoint)
        except (ApiError, requests.RequestException):
            continue
        update_tokens(record, result)
        record["write_upgrade_attempted"] = True
        return


LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail Console — Sign in</title>
<style>
  body { margin: 0; background: #eef4f7; color: #1b2e40; font: 15px system-ui, sans-serif; }
  main { box-sizing: border-box; width: min(440px, 94vw); margin: 8vh auto; padding: 24px;
         background: white; border: 1px solid #dbe5ec; border-radius: 14px; }
  label { display: block; margin: 14px 0 5px; }
  input, select, button { box-sizing: border-box; width: 100%; padding: 10px; font: inherit;
                          border: 1px solid #b9cad6; border-radius: 8px; }
  button { margin-top: 16px; background: #175e85; color: white; cursor: pointer; }
  button:disabled { opacity: .55; }
  #error { color: #a42636; }
</style>
</head>
<body>
<main>
  <h1>Mail Console</h1>
  {% if oauth %}
  <p><a href="/auth/microsoft">Sign in with Microsoft</a></p>
  {% endif %}
  <form id="signin">
    <label for="kind">Token type</label>
    <select id="kind">
      <option value="refresh">Refresh token</option>
      <option value="access">Access token</option>
    </select>
    <label for="token">Microsoft token</label>
    <input id="token" type="password" required autocomplete="off">
    <label for="client">Original client ID</label>
    <select id="client">
      {% for client_id in client_ids %}
      <option value="{{ client_id }}">{{ client_id }}</option>
      {% endfor %}
    </select>
    <button id="submit">Sign in</button>
    <p id="error" role="alert"></p>
  </form>
</main>
<script>
const csrf = {{ csrf|tojson }};
const byId = id => document.getElementById(id);
byId('kind').onchange = () => { byId('client').disabled = byId('kind').value === 'access'; };
byId('signin').onsubmit = async event => {
  event.preventDefault();
  byId('error').textContent = '';
  byId('submit').disabled = true;
  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        kind: byId('kind').value,
        token: byId('token').value.trim(),
        client_id: byId('client').value
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Sign-in failed.');
    byId('token').value = '';
    location.replace('/');
  } catch (error) {
    byId('error').textContent = error.message;
  } finally {
    byId('submit').disabled = false;
  }
};
</script>
</body>
</html>"""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def home():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    try:
        account()
    except ApiError:
        return render_template_string(
            LOGIN_HTML,
            csrf=session["csrf"],
            client_ids=CLIENT_IDS,
            oauth=bool(OAUTH_CLIENT),
        )

    try:
        template = (ROOT / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        return app.response_class(
            "index.html is missing. Deploy it beside mailbox.py.",
            status=500,
            mimetype="text/plain",
        )

    return app.response_class(
        template.replace("'__CSRF__'", json.dumps(session["csrf"])),
        mimetype="text/html",
    )


@app.post("/login")
def login():
    values = json_object()
    token = str(values.get("token") or "").strip()
    kind = values.get("kind")
    client_id = str(values.get("client_id") or "").strip()

    if not token:
        raise ApiError("Enter a token.")

    if kind == "access":
        response = requests.get(
            GRAPH + "/me",
            params={"$select": PROFILE_FIELDS},
            headers={"Authorization": "Bearer " + token},
            timeout=10,
        )

        if response.status_code == 401:
            raise ApiError("Token rejected by Microsoft.", 401)
        if response.status_code == 403:
            raise ApiError(
                "Microsoft denied access to /me. Check User.Read and tenant policy.",
                403,
                code="under_scoped",
            )
        if not response.ok:
            raise ApiError(f"Microsoft /me validation failed ({response.status_code}).", 502)

        profile = response_object(response)
        if not profile:
            raise ApiError("Microsoft returned unreadable profile data.", 502)
        claims = token_claims(token)
        save_login(
            {"access_token": token},
            claims.get("azp") or claims.get("appid") or client_id,
            profile=profile,
        )
    elif kind == "refresh":
        if client_id not in CLIENT_IDS:
            raise ApiError("Select the client ID that issued your refresh token.")
        result = token_request({
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": token,
            "scope": REFRESH_SCOPES,
        })
        save_login(result, client_id, refresh=token)
    else:
        raise ApiError("Choose an access token or refresh token.")

    return {"ok": True}


@app.post("/logout")
@app.post("/api/logout")
def logout():
    with STORE_LOCK:
        STORE.pop(session.get("sid"), None)
    session.clear()
    return {"ok": True}


@app.get("/auth/microsoft")
def microsoft_login():
    if not OAUTH_CLIENT:
        raise ApiError("Microsoft application registration is not configured.")

    extra_features = {
        "tasks": "Tasks.ReadWrite",
        "groups": "GroupMember.Read.All",
        "shared": (
            "Mail.ReadWrite.Shared Mail.Send.Shared "
            "Calendars.ReadWrite.Shared Contacts.ReadWrite.Shared"
        ),
    }
    extra = extra_features.get(request.args.get("feature"), "")
    scopes = f"{SCOPES} {extra}".strip()
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    session.update(oauth_state=state, verifier=verifier, requested_scopes=scopes)

    return redirect(LOGIN_BASE + "/authorize?" + urlencode({
        "client_id": OAUTH_CLIENT,
        "response_type": "code",
        "redirect_uri": PUBLIC_URL + "/auth/callback",
        "scope": scopes,
        "prompt": "select_account",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }))


@app.get("/auth/callback")
def oauth_callback():
    state = session.pop("oauth_state", "")
    verifier = session.pop("verifier", "")
    scopes = session.pop("requested_scopes", SCOPES)
    if not state or not verifier or not secrets.compare_digest(
        state, request.args.get("state", "")
    ):
        raise ApiError("Sign-in state expired. Start sign-in again.")

    code = request.args.get("code")
    if not code:
        raise ApiError("Microsoft sign-in was cancelled or denied.", 401)

    values = {
        "client_id": OAUTH_CLIENT,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": PUBLIC_URL + "/auth/callback",
        "scope": scopes,
    }
    if OAUTH_SECRET:
        values["client_secret"] = OAUTH_SECRET

    save_login(token_request(values), OAUTH_CLIENT, managed=True)
    return redirect("/")


def validate_graph_path(path):
    if not isinstance(path, str) or not GRAPH_RESOURCE.fullmatch(path):
        raise ApiError("This Microsoft Graph resource is not enabled.")
    decoded = unquote(path)
    if (
        any(char in decoded for char in ("\\", "#", "?", "\r", "\n"))
        or any(segment in {".", ".."} for segment in decoded.split("/"))
    ):
        raise ApiError("This Microsoft Graph resource is not enabled.")


def permission_for(path, method):
    if "messageRules" in path:
        key = "rules_read" if method == "GET" else "rules_write"
        return "inbox rules", FEATURE_SCOPES[key]
    if "mailboxSettings" in path:
        return "mailbox settings", FEATURE_SCOPES["settings"]
    if "/todo" in path:
        return "tasks", FEATURE_SCOPES["tasks"]
    if "/memberOf" in path:
        return "group memberships", FEATURE_SCOPES["groups"]
    if "/calendar" in path or "/events" in path:
        scope = "Calendars.Read" if method == "GET" else "Calendars.ReadWrite"
        return "calendar", [scope]
    if "/contacts" in path:
        scope = "Contacts.Read" if method == "GET" else "Contacts.ReadWrite"
        return "contacts", [scope]
    if path.endswith(("/sendMail", "/send", "/reply", "/replyAll", "/forward")):
        return "sending mail", FEATURE_SCOPES["mail_send"]
    if method == "GET":
        return "reading mail", FEATURE_SCOPES["mail_read"]
    return "managing mail", FEATURE_SCOPES["mail_write"]


def graph_error(response, path, method, record):
    result = response_object(response)
    details = result.get("error")
    if not isinstance(details, dict):
        details = {}
    code = details.get("code") or "GraphError"
    message = details.get("message") or "Microsoft rejected this operation."

    if response.status_code == 403:
        feature, required = permission_for(path, method)
        inner = details.get("innerError")
        inner = inner if isinstance(inner, dict) else {}
        raise ApiError(
            f"Microsoft denied the {feature} request. {message}",
            403,
            code="permission_required",
            feature=feature,
            required=required,
            details={
                "graphCode": code,
                "method": method,
                "path": path,
                "requestId": response.headers.get("request-id") or inner.get("request-id"),
                "scopeHint": scope_hints(record),
            },
        )

    raise ApiError(f"{code}: {message}", response.status_code)


def graph_request(method, path, query=None, payload=None, binary=False):
    validate_graph_path(path)
    record = account()

    with record["lock"]:
        upgrade_token_if_needed(record)
        if record["refresh"] and time.time() >= record["expires"] - 90:
            renew(record)

        for attempt in range(2):
            response = requests.request(
                method,
                GRAPH + path,
                params=query,
                json=payload,
                headers={
                    "Authorization": "Bearer " + record["access"],
                    "Prefer": 'outlook.body-content-type="html"',
                },
                timeout=25,
                allow_redirects=False,
            )
            if response.status_code == 401 and attempt == 0 and record["refresh"]:
                renew(record)
                continue
            break

    if not 200 <= response.status_code < 300:
        graph_error(response, path, method, record)
    if binary:
        return response.content, response.headers.get(
            "Content-Type", "application/octet-stream"
        )
    if not response.content:
        return {}

    try:
        result = response.json()
    except ValueError:
        raise ApiError("Microsoft returned an unexpected response.", 502) from None

    if isinstance(result, dict) and isinstance(result.get("body"), dict):
        images = {}
        if method == "GET" and MESSAGE_RESOURCE.fullmatch(path):
            try:
                images, missing = embedded_message_images(path, result["body"])
                if missing:
                    result["imageNotice"] = "Some embedded images were unavailable."
            except (ApiError, requests.RequestException):
                result["imageNotice"] = "Some embedded images could not be retrieved."
        result["safeBody"] = safe_message_body(result["body"], images)
    return result


@app.get("/api/session")
def session_info():
    record = account()
    if not record["who"]:
        try:
            profile = graph_request("GET", "/me", {"$select": PROFILE_FIELDS})
            record["who"] = profile_name(profile)
        except ApiError:
            record["who"] = "Mail Console"

    scopes = scope_hints(record)
    capabilities = {}
    for name, required in FEATURE_SCOPES.items():
        if scopes is None:
            status = "unknown"
        elif any(scope in scopes for scope in required):
            status = "available"
        else:
            status = "missing"
        capabilities[name] = {"state": status, "required": required}

    return {
        "capabilities": capabilities,
        "scopes": scopes,
        "oauth": bool(OAUTH_CLIENT),
        "refreshEnabled": bool(record["refresh"]),
        "expiresAt": record["expires"],
        "clientId": record["cid"],
        "who": record["who"],
    }


SAFE_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | set(
    "p div span br hr h1 h2 h3 h4 h5 h6 table thead tbody tfoot tr td th "
    "colgroup col img font blockquote pre code ul ol li sup sub center "
    "strike s u caption".split()
)
SAFE_CSS = CSSSanitizer(allowed_css_properties=[
    "color", "background-color", "font-family", "font-size", "font-weight",
    "font-style", "text-align", "text-decoration", "line-height", "padding",
    "margin", "border", "border-collapse", "width", "max-width", "height",
    "vertical-align", "white-space",
])
LINK_SCHEMES = {"http", "https", "mailto", "tel"}
IMAGE_TYPES = {"image/png", "image/gif", "image/jpeg", "image/webp", "image/bmp", "image/avif"}
INLINE_IMAGE = re.compile(
    r"data:image/(?:png|gif|jpeg|webp|bmp|avif);base64,[A-Za-z0-9+/=\s]+"
)
CID_PATTERN = re.compile(r"""cid:([^\s<>"']+)""", re.IGNORECASE)


def link_scheme(value):
    try:
        return urlsplit(value.strip()).scheme.lower()
    except ValueError:
        return ""


def safe_attribute(tag, name, value):
    if name == "style":
        return True
    if tag == "a":
        return name == "title" or (name == "href" and link_scheme(value) in LINK_SCHEMES)
    if tag == "img":
        return name in {"alt", "width", "height"} or (
            name == "src"
            and (link_scheme(value) in {"http", "https"} or bool(INLINE_IMAGE.fullmatch(value)))
        )
    return name in {
        "title", "align", "valign", "colspan", "rowspan", "width", "height",
        "border", "cellpadding", "cellspacing", "color", "face", "size",
    }


def safe_link(attributes, new=False):
    href = attributes.get((None, "href"), "")
    if link_scheme(href) not in LINK_SCHEMES:
        return None
    attributes[(None, "target")] = "_blank"
    attributes[(None, "rel")] = "noopener noreferrer"
    return attributes


def normal_cid(value):
    return unquote(html.unescape(value)).strip("<>").casefold()


def safe_message_body(body, images=None):
    source = body.get("content") or ""
    if str(body.get("contentType") or "").lower() == "html":
        if images:
            source = CID_PATTERN.sub(
                lambda match: images.get(normal_cid(match.group(1)), match.group(0)),
                source,
            )
        source = re.sub(
            r"<(script|style|iframe|object|svg|math|form)\b[^>]*>.*?</\1\s*>",
            "",
            source,
            flags=re.IGNORECASE | re.DOTALL,
        )
    else:
        source = "<pre>" + html.escape(source) + "</pre>"

    cleaned = bleach.clean(
        source,
        tags=SAFE_TAGS,
        attributes=safe_attribute,
        protocols=[*LINK_SCHEMES, "data"],
        css_sanitizer=SAFE_CSS,
        strip=True,
    )
    return bleach.linkifier.Linker(
        callbacks=[safe_link], skip_tags=["code"], parse_email=True
    ).linkify(cleaned)


def graph_next_query(next_link, path):
    try:
        link = urlsplit(next_link)
    except (TypeError, ValueError):
        raise ApiError("Microsoft returned an invalid pagination URL.", 502) from None

    if (
        link.scheme != "https"
        or link.netloc != "graph.microsoft.com"
        or unquote(link.path) != unquote("/v1.0" + path)
    ):
        raise ApiError("Microsoft returned an unexpected pagination URL.", 502)
    return parse_qsl(link.query, keep_blank_values=True)


def embedded_message_images(path, body):
    wanted = {
        normal_cid(match.group(1))
        for match in CID_PATTERN.finditer(body.get("content") or "")
    }
    if not wanted:
        return {}, False

    attachment_path = path + "/attachments"
    query = {"$top": 100}
    images = {}
    total = 0

    for _ in range(20):
        result = graph_request("GET", attachment_path, query)
        for attachment in result.get("value", []):
            cid = normal_cid(attachment.get("contentId") or "")
            if cid not in wanted or cid in images:
                continue
            mime = (attachment.get("contentType") or "").split(";")[0].lower()
            if mime not in IMAGE_TYPES:
                continue
            encoded = attachment.get("contentBytes")
            if not encoded and attachment.get("id"):
                detail = graph_request(
                    "GET", attachment_path + "/" + quote(attachment["id"], safe="")
                )
                encoded = detail.get("contentBytes")

            if (
                not isinstance(encoded, str)
                or len(encoded) > 16 * 1024 * 1024
                or total + len(encoded) > 32 * 1024 * 1024
            ):
                continue
            encoded = re.sub(r"\s+", "", encoded)
            try:
                base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            images[cid] = f"data:{mime};base64,{encoded}"
            total += len(encoded)

        next_link = result.get("@odata.nextLink")
        if wanted.issubset(images) or not next_link:
            break
        query = graph_next_query(next_link, attachment_path)

    return images, not wanted.issubset(images)


def graph_collection(path, query=None):
    rows = []
    for _ in range(101):
        result = graph_request("GET", path, query)
        rows.extend(result.get("value", []))
        next_link = result.get("@odata.nextLink")
        if not next_link:
            return rows
        query = graph_next_query(next_link, path)
    raise ApiError("Too many pages returned. Narrow the request.")


@app.post("/api/graph")
def graph_api():
    body = json_object()
    method = str(body.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PATCH", "DELETE"}:
        raise ApiError("Unsupported request method.")
    return jsonify(graph_request(
        method, body.get("path", ""), body.get("query"), body.get("payload")
    ))


@app.post("/api/download")
def download():
    body = json_object()
    path = body.get("path", "")
    if not isinstance(path, str) or not DOWNLOAD_RESOURCE.fullmatch(path):
        raise ApiError("Invalid download path.")

    content, content_type = graph_request("GET", path, binary=True)
    name = re.sub(r"[^a-zA-Z0-9._ -]", "_", str(body.get("name") or "download"))[:120]
    response = app.response_class(content, content_type=content_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return response


@app.get("/source.zip")
def source_zip():
    if os.getenv("ENABLE_SOURCE_DOWNLOAD") != "1":
        raise ApiError("Source download is disabled.", 404)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("mailbox.py", "index.html", "requirements.txt", "README.txt", "FEATURES.txt"):
            path = ROOT / name
            if path.is_file():
                archive.write(path, "outlook-mailbox/" + name)

    response = app.response_class(buffer.getvalue(), content_type="application/zip")
    response.headers["Content-Disposition"] = 'attachment; filename="outlook-mailbox.zip"'
    return response


@app.get("/api/folders")
def folders():
    return jsonify(folders=graph_collection("/me/mailFolders", {
        "$top": 100,
        "$select": (
            "id,displayName,parentFolderId,totalItemCount,"
            "unreadItemCount,childFolderCount"
        ),
    }))


@app.get("/api/messages")
def messages():
    folder = request.args.get("folder", "inbox").strip() or "inbox"
    path = "/me/messages" if folder == "all" else (
        "/me/mailFolders/" + quote(folder, safe="") + "/messages"
    )
    search = request.args.get("search", "").replace("\\", "").replace('"', "").strip()
    unread = not search and request.args.get("unread") == "1"

    query = {
        "$top": max(1, bounded_number("top", 20, 50)),
        "$select": (
            "id,subject,from,receivedDateTime,isRead,hasAttachments,"
            "bodyPreview,importance,flag,toRecipients,sentDateTime,isDraft"
        ),
    }
    if search:
        query["$search"] = f'"{search}"'
    else:
        if unread:
            query["$filter"] = "isRead eq false"
        else:
            query["$orderby"] = "receivedDateTime desc"
        skip = bounded_number("skip", 0, 1000000)
        if skip:
            query["$skip"] = skip

    view = [session.get("sid"), path, search, unread]
    cursor = request.args.get("cursor")
    if cursor:
        try:
            page = CURSORS.loads(cursor, max_age=1800)
        except BadSignature:
            raise ApiError("This page link has expired. Refresh the mailbox.") from None
        if page.get("view") != view:
            raise ApiError("This page link belongs to a different mailbox view.")
        query = page["query"]

    result = graph_request("GET", path, query)
    next_link = result.get("@odata.nextLink")
    next_cursor = None
    if next_link:
        next_cursor = CURSORS.dumps({
            "view": view,
            "query": graph_next_query(next_link, path),
        })
    return jsonify(messages=result.get("value", []), cursor=next_cursor)


def message_path(message_id):
    return "/me/messages/" + quote(message_id, safe="")


@app.get("/api/messages/<path:mid>")
def message(mid):
    result = graph_request("GET", message_path(mid))
    result["safeHtml"] = result.get("safeBody") or safe_message_body(result.get("body") or {})
    return jsonify(result)


@app.delete("/api/messages/<path:mid>")
def delete_message(mid):
    graph_request("DELETE", message_path(mid))
    return jsonify(ok=True)


@app.post("/api/messages/<path:mid>/read")
def mark_read(mid):
    is_read = json_object().get("isRead", True)
    if not isinstance(is_read, bool):
        raise ApiError("isRead must be true or false.")
    graph_request("PATCH", message_path(mid), payload={"isRead": is_read})
    return jsonify(ok=True)


@app.post("/api/messages/<path:mid>/move")
def move_message(mid):
    destination = str(json_object().get("destinationId") or "").strip()
    if not destination:
        raise ApiError("Choose a destination folder.")
    return jsonify(graph_request(
        "POST", message_path(mid) + "/move", payload={"destinationId": destination}
    ))


def addresses(value):
    return [
        {"emailAddress": {"address": address.strip()}}
        for address in re.split(r"[,;]", str(value or ""))
        if address.strip()
    ]


@app.post("/api/send")
def send_message():
    body = json_object()
    to = addresses(body.get("to"))
    if not to:
        raise ApiError("Enter at least one recipient.")
    graph_request("POST", "/me/sendMail", payload={
        "message": {
            "subject": str(body.get("subject") or ""),
            "body": {"contentType": "HTML", "content": str(body.get("body") or "")},
            "toRecipients": to,
            "ccRecipients": addresses(body.get("cc")),
            "bccRecipients": addresses(body.get("bcc")),
        },
        "saveToSentItems": True,
    })
    return jsonify(ok=True)


@app.get("/api/rules")
def rules():
    rows = graph_collection(MAIL_RULES)
    rows.sort(key=lambda rule: rule.get("sequence", 0))
    return jsonify(rules=rows)


def rule_payload(body, existing=None):
    previous = existing or {}
    name = str(body.get("displayName", previous.get("displayName", "")) or "").strip()
    if not name:
        raise ApiError("Enter a rule name.")

    conditions = dict(previous.get("conditions") or {})
    actions = dict(previous.get("actions") or {})

    for field, graph_field in (
        ("fromContains", "senderContains"),
        ("subjectContains", "subjectContains"),
    ):
        if field in body:
            terms = [term.strip() for term in str(body[field] or "").split(",") if term.strip()]
            conditions.pop(graph_field, None)
            if terms:
                conditions[graph_field] = terms

    if "moveTo" in body:
        actions.pop("moveToFolder", None)
        if body["moveTo"]:
            actions["moveToFolder"] = str(body["moveTo"])

    for field, graph_field in (("delete", "delete"), ("markRead", "markAsRead")):
        if field in body:
            if not isinstance(body[field], bool):
                raise ApiError(f"{field} must be true or false.")
            actions.pop(graph_field, None)
            if body[field]:
                actions[graph_field] = True

    if actions.get("delete") and actions.get("moveToFolder"):
        raise ApiError("Choose either moving or deleting.")
    if not any(value for key, value in actions.items() if key != "stopProcessingRules"):
        raise ApiError("Choose at least one rule action.")

    payload = {"displayName": name, "conditions": conditions, "actions": actions}
    if not existing:
        payload.update(sequence=1, isEnabled=True)
    return payload


@app.post("/api/rules")
def create_rule():
    payload = rule_payload(json_object())
    return jsonify(graph_request("POST", MAIL_RULES, payload=payload))


@app.patch("/api/rules/<path:rid>")
def update_rule(rid):
    body = json_object()
    path = MAIL_RULES + "/" + quote(rid, safe="")
    previous = graph_request("GET", path)
    return jsonify(graph_request("PATCH", path, payload=rule_payload(body, previous)))


@app.delete("/api/rules/<path:rid>")
def delete_rule(rid):
    graph_request("DELETE", MAIL_RULES + "/" + quote(rid, safe=""))
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
```
