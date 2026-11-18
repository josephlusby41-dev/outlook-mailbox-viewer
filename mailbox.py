import base64
import hashlib
import html
import json
import os
import re
import secrets
import threading
import time
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
LOGIN = "https://login.microsoftonline.com/common/oauth2/v2.0"
PUBLIC_URL = os.getenv(
    "PUBLIC_URL", "https://outlook-mailbox-viewer.onrender.com"
).rstrip("/")
CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")
CLIENT_IDS = [
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1b730954-1685-4b74-9bfd-dac224a7b894",
]
SCOPES = "offline_access User.Read Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite"
REFRESH_SCOPES = "https://graph.microsoft.com/.default offline_access"
PROFILE_FIELDS = "displayName,mail,userPrincipalName"
FOLDER_FIELDS = "id,displayName,parentFolderId,totalItemCount,unreadItemCount,childFolderCount"
MESSAGE_FIELDS = (
    "id,subject,from,toRecipients,receivedDateTime,sentDateTime,isRead,"
    "hasAttachments,bodyPreview,importance,flag,isDraft"
)
RULES = "/me/mailFolders/inbox/messageRules"
CURSORS = URLSafeTimedSerializer(app.secret_key, salt="mailbox-messages-v2")
ACCOUNTS = {}
ACCOUNTS_LOCK = threading.RLock()
IDLE_LIMIT = 7200


class MailError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@app.errorhandler(MailError)
def mail_error(error):
    return jsonify(ok=False, message=str(error)), error.status


@app.errorhandler(requests.RequestException)
def network_error(error):
    return jsonify(ok=False, message="Microsoft could not be reached. Please retry."), 502


@app.before_request
def check_csrf():
    if request.method in {"POST", "PATCH", "DELETE"}:
        expected = session.get("csrf", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            raise MailError("This page expired. Reload it and try again.", 403)


@app.after_request
def set_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def json_body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise MailError("Send a JSON object with this request.")
    return value


def response_json(response):
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def token_request(values):
    response = requests.post(LOGIN + "/token", data=values, timeout=20)
    data = response_json(response)
    if not response.ok:
        code = str(data.get("error") or "sign_in_failed")
        codes = data.get("error_codes")
        if isinstance(codes, list) and codes and isinstance(codes[0], int):
            code += f", AADSTS{codes[0]}"
        raise MailError(f"Microsoft sign-in failed ({code}).", 401)
    if not data.get("access_token"):
        raise MailError("Microsoft did not return an access token.", 502)
    return data


def expires_at(data):
    try:
        return time.time() + int(data.get("expires_in", 3600))
    except (ValueError, TypeError):
        return time.time() + 3600


def display_name(profile):
    return (
        profile.get("mail") or profile.get("userPrincipalName")
        or profile.get("displayName") or "Mail Console"
    )


def save_account(data, client_id, *, refresh="", managed=False, name=""):
    now = time.time()
    with ACCOUNTS_LOCK:
        for key, record in list(ACCOUNTS.items()):
            if now - record["used"] > IDLE_LIMIT:
                ACCOUNTS.pop(key, None)
        ACCOUNTS.pop(session.get("account"), None)
        session.clear()
        key = secrets.token_urlsafe(32)
        session.update(account=key, csrf=secrets.token_urlsafe(32))
        ACCOUNTS[key] = {
            "access": data["access_token"],
            "refresh": data.get("refresh_token") or refresh,
            "client": client_id,
            "managed": managed,
            "scopes": data.get("scope"),
            "name": name,
            "expires": expires_at(data),
            "used": now,
            "lock": threading.RLock(),
        }


def current_account():
    key = session.get("account")
    with ACCOUNTS_LOCK:
        record = ACCOUNTS.get(key)
        if not record or time.time() - record["used"] > IDLE_LIMIT:
            ACCOUNTS.pop(key, None)
            raise MailError("Your session expired. Sign in again.", 401)
        record["used"] = time.time()
        return record


def renew(record):
    values = {
        "client_id": record["client"],
        "grant_type": "refresh_token",
        "refresh_token": record["refresh"],
        "scope": (
            record.get("scopes") or SCOPES
            if record["managed"] else REFRESH_SCOPES
        ),
    }
    if record["managed"] and CLIENT_SECRET:
        values["client_secret"] = CLIENT_SECRET
    data = token_request(values)
    record.update(
        access=data["access_token"],
        refresh=data.get("refresh_token") or record["refresh"],
        scopes=data.get("scope") or record.get("scopes"),
        expires=expires_at(data),
    )


LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail Console — Sign in</title>
<style>
body{margin:0;background:#edf4f7;color:#172c40;font:15px system-ui,sans-serif}
main{box-sizing:border-box;width:min(440px,94vw);margin:9vh auto;padding:24px;background:white;border:1px solid #cadce6;border-radius:14px}
label{display:block;margin:12px 0 5px}
input,select,button{box-sizing:border-box;width:100%;padding:9px;border:1px solid #a8bdcb;border-radius:7px;font:inherit}
button{margin-top:15px;background:#175e85;color:white;cursor:pointer}
a{color:#175e85}
#error{color:#a22639}
</style>
</head>
<body>
<main>
<h1>Mail Console</h1>
{% if oauth %}<p><a href="/auth/microsoft">Sign in with Microsoft</a></p>{% endif %}
<form id="form">
<label for="kind">Token type</label>
<select id="kind"><option value="refresh">Refresh token</option><option value="access">Access token</option></select>
<label for="token">Microsoft token</label>
<input id="token" type="password" required autocomplete="off">
<label for="client">Original client ID</label>
<select id="client">{% for id in ids %}<option value="{{ id }}">{{ id }}</option>{% endfor %}</select>
<button id="submit">Sign in</button>
<p id="error" role="alert"></p>
</form>
</main>
<script>
const csrf = {{ csrf|tojson }};
const el = id => document.getElementById(id);
el('kind').onchange = () => { el('client').disabled = el('kind').value === 'access'; };
el('form').onsubmit = async event => {
  event.preventDefault();
  el('submit').disabled = true;
  el('error').textContent = '';
  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json', 'X-CSRF-Token':csrf},
      body: JSON.stringify({kind:el('kind').value,token:el('token').value.trim(),client_id:el('client').value}),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || 'Sign-in failed.');
    el('token').value = '';
    location.replace('/');
  } catch (error) {
    el('error').textContent = error.message;
  } finally {
    el('submit').disabled = false;
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
        current_account()
    except MailError:
        return render_template_string(
            LOGIN_HTML, csrf=session["csrf"], ids=CLIENT_IDS, oauth=bool(CLIENT_ID)
        )

    try:
        page = (ROOT / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        raise MailError("index.html is missing. Put it beside mailbox.py.", 500) from None

    return app.response_class(
        page.replace("'__CSRF__'", json.dumps(session["csrf"])),
        mimetype="text/html",
    )


@app.post("/login")
def login():
    body = json_body()
    kind = body.get("kind")
    token = str(body.get("token") or "").strip()
    client = str(body.get("client_id") or "").strip()

    if not token:
        raise MailError("Enter a token.")

    if kind == "access":
        response = requests.get(
            GRAPH + "/me",
            params={"$select": PROFILE_FIELDS},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise MailError(
                f"Microsoft Graph rejected the /me request ({response.status_code}).",
                response.status_code if response.status_code in {401, 403} else 502,
            )
        save_account(
            {"access_token": token}, client,
            name=display_name(response_json(response)),
        )
    elif kind == "refresh":
        if client not in CLIENT_IDS:
            raise MailError("Choose the client ID that issued your refresh token.")
        data = token_request({
            "client_id": client,
            "grant_type": "refresh_token",
            "refresh_token": token,
            "scope": REFRESH_SCOPES,
        })
        save_account(data, client, refresh=token)
    else:
        raise MailError("Choose an access token or refresh token.")
    return {"ok": True}


@app.get("/auth/microsoft")
def microsoft_login():
    if not CLIENT_ID:
        raise MailError("Microsoft sign-in is not configured.")

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    session.update(oauth_state=state, oauth_verifier=verifier)
    return redirect(LOGIN + "/authorize?" + urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": PUBLIC_URL + "/auth/callback",
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }))


@app.get("/auth/callback")
def microsoft_callback():
    state = session.pop("oauth_state", "")
    verifier = session.pop("oauth_verifier", "")
    if not state or not verifier or not secrets.compare_digest(
        state, request.args.get("state", "")
    ):
        raise MailError("Sign-in expired. Start sign-in again.")
    code = request.args.get("code")
    if not code:
        raise MailError("Microsoft sign-in was cancelled or denied.", 401)
    values = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": PUBLIC_URL + "/auth/callback",
        "scope": SCOPES,
    }
    if CLIENT_SECRET:
        values["client_secret"] = CLIENT_SECRET
    save_account(token_request(values), CLIENT_ID, managed=True)
    return redirect("/")


@app.post("/logout")
@app.post("/api/logout")
def logout():
    with ACCOUNTS_LOCK:
        ACCOUNTS.pop(session.get("account"), None)
    session.clear()
    return {"ok": True}


GRAPH_PATH = re.compile(
    r"/(?:me|users/[^/]+)"
    r"(?:/(?:mailFolders|messages|sendMail|mailboxSettings)(?:/.*)?)?"
)
MESSAGE_PATH = re.compile(r"/me/messages/[^/]+")
DOWNLOAD_PATH = re.compile(r"/me/messages/[^/]+/attachments/[^/]+/\$value")
FOLDER_MESSAGE_PATH = re.compile(r"/me/mailFolders/[^/]+/messages")


def validate_path(path):
    if not isinstance(path, str) or not GRAPH_PATH.fullmatch(path):
        raise MailError("This Microsoft Graph resource is not enabled.")
    decoded = unquote(path)
    if (
        any(char in decoded for char in "\\?#\r\n")
        or any(part in {".", ".."} for part in decoded.split("/"))
    ):
        raise MailError("Invalid Microsoft Graph path.")


def graph(method, path, query=None, payload=None, binary=False):
    validate_path(path)
    record = current_account()

    with record["lock"]:
        if record["refresh"] and time.time() >= record["expires"] - 90:
            renew(record)
        for attempt in range(2):
            response = requests.request(
                method, GRAPH + path, params=query, json=payload,
                headers={"Authorization": "Bearer " + record["access"]},
                timeout=25, allow_redirects=False,
            )
            if response.status_code == 401 and attempt == 0 and record["refresh"]:
                renew(record)
                continue
            break

    if not 200 <= response.status_code < 300:
        error = response_json(response).get("error")
        error = error if isinstance(error, dict) else {}
        code = error.get("code") or "GraphError"
        message = error.get("message") or "Microsoft rejected this request."
        status = response.status_code if response.status_code >= 400 else 502
        raise MailError(f"{code}: {message}", status)

    if binary:
        return response.content
    if not response.content:
        return {}
    try:
        data = response.json()
    except ValueError:
        raise MailError("Microsoft returned an unexpected response.", 502) from None
    if not isinstance(data, dict):
        raise MailError("Microsoft returned an unexpected response.", 502)
    return data


@app.get("/api/session")
def account_info():
    record = current_account()
    if not record["name"]:
        try:
            record["name"] = display_name(graph("GET", "/me", {"$select": PROFILE_FIELDS}))
        except MailError:
            return jsonify(who="Mail Console")
    return jsonify(
        who=record["name"], expiresAt=record["expires"],
        clientId=record["client"], refreshEnabled=bool(record["refresh"]),
        oauth=bool(CLIENT_ID),
    )


def next_page(link_value, original_path, *, folder_messages=False):
    try:
        link = urlsplit(link_value)
    except (TypeError, ValueError):
        raise MailError("Microsoft returned an invalid next-page link.", 502) from None

    if (
        link.scheme != "https" or link.netloc != "graph.microsoft.com"
        or not link.path.startswith("/v1.0/") or link.fragment
    ):
        raise MailError("Microsoft returned an unexpected next-page link.", 502)

    path = link.path[len("/v1.0"):]
    validate_path(path)
    expected = re.sub(r"^/users/[^/]+/", "/me/", unquote(original_path))
    actual = re.sub(r"^/users/[^/]+/", "/me/", unquote(path))
    resolved_folder = (
        folder_messages
        and FOLDER_MESSAGE_PATH.fullmatch(expected)
        and FOLDER_MESSAGE_PATH.fullmatch(actual)
    )
    if actual != expected and not resolved_folder:
        raise MailError("Microsoft returned a next page for a different view.", 502)

    return path, parse_qsl(link.query, keep_blank_values=True)


def collection(path, query=None):
    rows = []
    original = path
    for _ in range(100):
        result = graph("GET", path, query)
        rows.extend(result.get("value") or [])
        continuation = result.get("@odata.nextLink")
        if not continuation:
            return rows
        path, query = next_page(continuation, original)
    raise MailError("Microsoft returned too many pages.", 502)


@app.get("/api/folders")
def folders():
    parent = request.args.get("parent", "").strip()
    path = "/me/mailFolders"
    if parent:
        path += f"/{quote(parent, safe='')}/childFolders"
    return jsonify(folders=collection(path, {"$top": 100, "$select": FOLDER_FIELDS}))


@app.get("/api/messages")
def messages():
    current_account()
    folder = request.args.get("folder", "inbox").strip() or "inbox"
    path = "/me/messages" if folder == "all" else (
        f"/me/mailFolders/{quote(folder, safe='')}/messages"
    )
    search = request.args.get("search", "").replace("\\", "").replace('"', "").strip()
    unread = not search and request.args.get("unread") == "1"
    query = {"$top": 25, "$select": MESSAGE_FIELDS}

    if search:
        query["$search"] = f'"{search}"'
    elif unread:
        query["$filter"] = "isRead eq false"
    else:
        query["$orderby"] = "receivedDateTime desc"

    binding = hashlib.sha256(session["account"].encode()).hexdigest()
    view = [binding, path, search, unread]
    page_path = path
    cursor = request.args.get("cursor")

    if cursor:
        try:
            saved = CURSORS.loads(cursor, max_age=1800)
        except BadSignature:
            raise MailError("This page link expired. Refresh the mailbox.") from None
        if saved.get("view") != view:
            raise MailError("This page link belongs to a different mailbox view.")
        page_path, query = saved["path"], saved["query"]

    result = graph("GET", page_path, query)
    continuation = result.get("@odata.nextLink")
    warning = None
    cursor = None
    if continuation:
        try:
            page_path, page_query = next_page(continuation, path, folder_messages=True)
        except MailError:
            warning = "Messages loaded, but Microsoft returned an unusable next page."
        else:
            cursor = CURSORS.dumps({"view": view, "path": page_path, "query": page_query})
    return jsonify(messages=result.get("value") or [], cursor=cursor, warning=warning)


SAFE_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | set(
    "p div span br hr img h1 h2 h3 h4 h5 h6 table thead tbody tfoot tr th td "
    "caption blockquote pre code sup sub s u".split()
)
SAFE_CSS = CSSSanitizer(allowed_css_properties=[
    "color", "background-color", "font-family", "font-size", "font-weight",
    "font-style", "text-align", "text-decoration", "line-height", "padding",
    "margin", "border", "border-collapse", "width", "height", "vertical-align",
])
SAFE_ATTRIBUTES = {
    "*": ["style", "title"],
    "a": ["href", "title"],
    "img": ["src", "alt", "width", "height"],
    "th": ["colspan", "rowspan"],
    "td": ["colspan", "rowspan"],
}


def safe_html(body):
    content = str(body.get("content") or "")
    if str(body.get("contentType") or "").lower() != "html":
        return "<pre>" + html.escape(content) + "</pre>"
    content = re.sub(
        r"<(script|style|iframe|object|svg|math|form)\b[^>]*>.*?</\1\s*>",
        "", content, flags=re.IGNORECASE | re.DOTALL,
    )
    return bleach.clean(
        content, tags=SAFE_TAGS, attributes=SAFE_ATTRIBUTES,
        protocols=["https", "http", "mailto", "tel"],
        css_sanitizer=SAFE_CSS, strip=True,
    )


def message_path(mid):
    return "/me/messages/" + quote(mid, safe="")


@app.get("/api/messages/<path:mid>")
def message(mid):
    result = graph("GET", message_path(mid))
    result["safeHtml"] = safe_html(result.get("body") or {})
    return jsonify(result)


@app.delete("/api/messages/<path:mid>")
def delete_message(mid):
    graph("DELETE", message_path(mid))
    return jsonify(ok=True)


@app.post("/api/messages/<path:mid>/read")
def mark_read(mid):
    value = json_body().get("isRead", True)
    if not isinstance(value, bool):
        raise MailError("isRead must be true or false.")
    graph("PATCH", message_path(mid), payload={"isRead": value})
    return jsonify(ok=True)


@app.post("/api/messages/<path:mid>/move")
def move_message(mid):
    destination = str(json_body().get("destinationId") or "").strip()
    if not destination:
        raise MailError("Choose a destination folder.")
    return jsonify(graph(
        "POST", message_path(mid) + "/move", payload={"destinationId": destination}
    ))


@app.get("/api/messages/<path:mid>/attachments")
def attachments(mid):
    return jsonify(attachments=collection(message_path(mid) + "/attachments", {
        "$select": "id,name,isInline,contentType,size",
    }))


@app.post("/api/download")
def download():
    body = json_body()
    path = body.get("path", "")
    if not isinstance(path, str) or not DOWNLOAD_PATH.fullmatch(path):
        raise MailError("Invalid attachment path.")
    name = re.sub(r"[^a-zA-Z0-9._ -]", "_", str(body.get("name") or "attachment"))[:120]
    content = graph("GET", path, binary=True)
    response = app.response_class(content, mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return response


@app.post("/api/graph")
def mailbox_action():
    body = json_body()
    method = str(body.get("method") or "").upper()
    path = body.get("path", "")
    payload = body.get("payload")
    if not isinstance(path, str):
        raise MailError("Invalid mailbox action.")
    allowed = (
        (method == "POST" and path == "/me/messages")
        or (method == "PATCH" and MESSAGE_PATH.fullmatch(path))
        or (method == "POST" and re.fullmatch(
            r"/me/messages/[^/]+/(?:send|reply|replyAll|forward)", path
        ))
    )
    if not allowed:
        raise MailError("This mailbox action is not enabled.")
    return jsonify(graph(method, path, payload=payload))


def recipients(value):
    return [
        {"emailAddress": {"address": address.strip()}}
        for address in re.split(r"[,;]", str(value or ""))
        if address.strip()
    ]


@app.post("/api/send")
def send_message():
    body = json_body()
    to = recipients(body.get("to"))
    if not to:
        raise MailError("Enter at least one recipient.")
    graph("POST", "/me/sendMail", payload={
        "message": {
            "subject": str(body.get("subject") or ""),
            "body": {"contentType": "Text", "content": str(body.get("body") or "")},
            "toRecipients": to,
            "ccRecipients": recipients(body.get("cc")),
            "bccRecipients": recipients(body.get("bcc")),
        },
        "saveToSentItems": True,
    })
    return jsonify(ok=True)


@app.get("/api/rules")
def rules():
    entries = collection(RULES)
    return jsonify(rules=sorted(entries, key=lambda item: item.get("sequence", 0)))


def build_rule(body, previous=None):
    previous = previous or {}
    name = str(body.get("displayName") or "").strip()
    if not name:
        raise MailError("Enter a rule name.")
    conditions = dict(previous.get("conditions") or {})
    actions = dict(previous.get("actions") or {})
    for field, target in (("fromContains", "senderContains"), ("subjectContains", "subjectContains")):
        terms = [part.strip() for part in str(body.get(field) or "").split(",") if part.strip()]
        conditions.pop(target, None)
        if terms:
            conditions[target] = terms

    for field, target in (("moveTo", "moveToFolder"), ("delete", "delete"), ("markRead", "markAsRead")):
        actions.pop(target, None)
        if body.get(field):
            actions[target] = body[field]

    if actions.get("delete") and actions.get("moveToFolder"):
        raise MailError("Choose one destination action: move or delete.")
    if not any(value for key, value in actions.items() if key != "stopProcessingRules"):
        raise MailError("Choose at least one rule action.")
    result = {"displayName": name, "conditions": conditions, "actions": actions}
    if not previous:
        result.update(sequence=1, isEnabled=True)
    return result


@app.post("/api/rules")
def create_rule():
    return jsonify(graph("POST", RULES, payload=build_rule(json_body())))


@app.patch("/api/rules/<path:rid>")
def update_rule(rid):
    path = RULES + "/" + quote(rid, safe="")
    previous = graph("GET", path)
    return jsonify(graph("PATCH", path, payload=build_rule(json_body(), previous)))


@app.delete("/api/rules/<path:rid>")
def delete_rule(rid):
    graph("DELETE", RULES + "/" + quote(rid, safe=""))
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
