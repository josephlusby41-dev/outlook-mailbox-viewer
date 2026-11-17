# mailbox.py — Full OWA-style Office 365 mailbox viewer
# Start command: gunicorn mailbox:app --workers 1 --threads 8
import os, requests
from flask import Flask, request, session, redirect, url_for, render_template_string

CLIENT_ID = os.environ.get("CLIENT_ID", "27922004-5251-4030-b22d-91ecd9a37ea4")
AUTH = "https://login.microsoftonline.com/common/oauth2/v2.0"
GRAPH = "https://graph.microsoft.com/v1.0"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-please")

app = Flask(__name__)
app.secret_key = SECRET_KEY

STYLE = """
<style>
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f3f2f1}
.top{background:#0078d4;color:#fff;padding:12px 20px;display:flex;gap:20px;align-items:center}
.top a{color:#fff;text-decoration:none;font-weight:600;padding:6px 12px;border-radius:4px}
.top a:hover,.top a.active{background:rgba(255,255,255,.2)}
.wrap{display:flex;max-width:1200px;margin:20px auto;gap:20px;padding:0 15px}
.folders{width:220px;background:#fff;border-radius:8px;padding:10px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.folders a{display:block;padding:9px 12px;color:#323130;text-decoration:none;border-radius:4px}
.folders a:hover{background:#e1dfdd}
.folders a.sel{background:#cfe4fc;font-weight:600}
.list{flex:1;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.msgrow{display:flex;padding:12px 15px;border-bottom:1px solid #edebe9;cursor:pointer;gap:10px;align-items:center}
.msgrow:hover{background:#f3f2f1}
.msgrow .from{width:200px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msgrow.unread .from,.msgrow.unread .subj{font-weight:800}
.msgrow .subj{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msgrow .date{color:#605e5c;font-size:12px}
.badge{background:#0078d4;color:#fff;border-radius:10px;font-size:11px;padding:1px 7px}
.view{padding:25px}
.view h2{margin:0 0 5px}
.view .meta{color:#605e5c;font-size:13px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid #edebe9}
.body-html{line-height:1.6}
.btn{background:#0078d4;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px;margin-right:6px;margin-bottom:8px}
.btn.gray{background:#605e5c}
input,select,textarea{padding:8px;border:1px solid #8a8886;border-radius:4px;font-size:14px;width:100%;box-sizing:border-box}
label{display:block;margin:12px 0 4px;font-weight:600}
.box{max-width:700px;margin:30px auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.searchbar{padding:12px 15px;border-bottom:1px solid #edebe9;display:flex;gap:8px}
.searchbar input{flex:1}
.pages{padding:12px;text-align:center}
.pages a{margin:0 4px;text-decoration:none;color:#0078d4}
.dark body,.dark{background:#1b1a19}
.dark .list,.dark .folders,.dark .box{background:#292827;color:#fff}
.dark .msgrow{border-color:#3b3a39}.dark .msgrow:hover{background:#323130}
.dark input,.dark textarea{background:#323130;color:#fff;border-color:#605e5c}
</style>
"""

BASE = """<!doctype html><html><head><meta charset=utf-8>
<title>Outlook</title><meta name=viewport content="width=device-width,initial-scale=1">
{{style}}</head><body class="{{theme}}">
<div class=top>
 <b>Outlook</b>
 <a href="/?folder=Inbox">Mail</a>
 <a href="/search">Search</a>
 <a href="/settings">Settings</a>
 <a href="/logout" style="margin-left:auto">Sign out</a>
</div>{{content}}</body></html>"""

def tok():
    r = requests.post(AUTH + "/token", data={
        "client_id": CLIENT_ID, "grant_type": "refresh_token",
        "refresh_token": session["rt"], "scope": "https://graph.microsoft.com/.default offline_access"})
    j = r.json()
    if "access_token" in j:
        session["rt"] = j.get("refresh_token", session["rt"])  # rotate
        return j["access_token"]
    session.clear()
    return None

def g(method, path, token, **kw):
    return requests.request(method, GRAPH + path, headers={"Authorization": "Bearer " + token}, **kw)

def page(content, active="mail"):
    return render_template_string(BASE, style=STYLE, content=content,
        theme=session.get("theme", "light"), active=active)

FOLDERS = ["Inbox","SentItems","Drafts","DeletedItems","JunkEmail","Archive"]

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

@app.route("/", methods=["GET"])
def inbox():
    if "rt" not in session: return login_page()
    t = tok()
    if not t: return login_page()
    f = request.args.get("folder", "Inbox")
    p = int(request.args.get("p", 1))
    per = int(session.get("per_page", 25))
    fr = g("GET", f"/me/mailFolders/{f}/messages?$top={per}&$skip={(p-1)*per}"
           "&$select=id,subject,from,receivedDateTime,isRead,hasAttachments&$orderby=receivedDateTime desc", t).json()
    total = fr.get("@odata.count", len(fr.get("value", [])))
    rows = ""
    for m in fr.get("value", []):
        nm = (m.get("from") or {}).get("emailAddress", {}).get("name", "(unknown)")
        att = " 📎" if m.get("hasAttachments") else ""
        rows += f"<div class='msgrow {'unread' if not m['isRead'] else ''}' onclick=\"location='/view/{m['id']}'\">"
        rows += f"<div class=from>{nm}</div><div class=subj>{m.get('subject') or '(no subject)'}{att}</div>"
        rows += f"<div class=date>{m['receivedDateTime'][:16].replace('T',' ')}"
        rows += (f" <span class=badge>{m['id'][:0]}</span>" if not m['isRead'] else "") + "</div></div>"
    nav = f"<div class=pages>Page {p} "
    if p > 1: nav += f"<a href='/?folder={f}&p={p-1}'>‹ Prev</a>"
    if total > p*per: nav += f"<a href='/?folder={f}&p={p+1}'>Next ›</a>"
    nav += "</div>"
    fl = "".join(f"<a class='{'sel' if x==f else ''}' href='/?folder={x}'>{x}</a>" for x in FOLDERS)
    content = f"<div class=wrap><div class=folders>{fl}</div><div class=list>{nav}{rows}{nav}</div></div>"
    return page(content)

@app.route("/view/<mid>")
def view(mid):
    t = tok()
    if not t: return login_page()
    m = g("GET", f"/me/messages/{mid}?$select=subject,from,toRecipients,body,receivedDateTime,isRead,attachments", t).json()
    g("PATCH", f"/me/messages/{mid}", t, json={"isRead": True})
    fr = (m.get("from") or {}).get("emailAddress", {}).get("address", "")
    to = ", ".join(r["emailAddress"]["address"] for r in m.get("toRecipients", []))
    body = m.get("body", {}).get("content", "")
    att = ""
    if m.get("hasAttachments"):
        a = g("GET", f"/me/messages/{mid}/attachments", t).json()
        att = "<h3>Attachments</h3>" + "".join(
            f"<p><a href='/attach/{mid}/{x['id']}'>{x['name']}</a></p>" for x in a.get("value", []))
    btns = f"""
    <a class=btn href="/reply/{mid}">Reply</a>
    <a class=btn href="/reply/{mid}?fw=1">Forward</a>
    <a class="btn gray" href="/del/{mid}">Delete</a>
    <a class="btn gray" href="/">Back</a>"""
    content = f"<div class=box><h2>{m.get('subject','(no subject)')}</h2>"
    content += f"<div class=meta>From: {fr}<br>To: {to}<br>{m['receivedDateTime'][:19].replace('T',' ')}</div>"
    content += f"<div class=body-html>{body}</div>{att}{btns}</div>"
    return page(content)

@app.route("/attach/<mid>/<aid>")
def attach(mid, aid):
    t = tok()
    if not t: return login_page()
    r = g("GET", f"/me/messages/{mid}/attachments/{aid}/$value", t)
    return r.content, 200, {"Content-Type": "application/octet-stream",
        "Content-Disposition": f"attachment; filename=attachment"}

@app.route("/reply/<mid>")
def reply(mid):
    t = tok()
    if not t: return login_page()
    fw = request.args.get("fw")
    m = g("GET", f"/me/messages/{mid}?$select=subject,from,toRecipients,body", t).json()
    if fw:
        to = ""; subj = "FW: " + (m.get("subject") or ""); orig = m.get("body", {}).get("content", "")
    else:
        to = (m.get("from") or {}).get("emailAddress", {}).get("address", "")
        subj = "RE: " + (m.get("subject") or "")
        orig = f"<br><hr>On {m.get('receivedDateTime','')} <b>{to}</b> wrote:<br>" + m.get("body", {}).get("content", "")
    return compose(to, subj, orig)

@app.route("/del/<mid>")
def deletemsg(mid):
    t = tok()
    if not t: return login_page()
    g("DELETE", f"/me/messages/{mid}", t)
    return redirect("/")

@app.route("/compose")
def compose(to="", subj="", body=""):
    c = f"""<div class=box><h2>New message</h2>
    <form method=post action=/send>
    <label>To</label><input name=to value="{to}">
    <label>Subject</label><input name=subj value="{subj}">
    <label>Message</label><textarea name=body rows=12>{body}</textarea><br><br>
    <button class=btn>Send</button> <a class="btn gray" href=/>Cancel</a></form></div>"""
    return page(c)

@app.route("/send", methods=["POST"])
def send():
    t = tok()
    if not t: return login_page()
    msg = {"message": {"subject": request.form["subj"],
        "body": {"contentType": "HTML", "content": request.form["body"].replace("\n", "<br>")},
        "toRecipients": [{"emailAddress": {"address": request.form["to"]}}]}}
    g("POST", "/me/sendMail", t, json=msg)
    return redirect("/?folder=SentItems")

@app.route("/search", methods=["GET", "POST"])
def search():
    t = tok()
    if not t: return login_page()
    q = request.args.get("q", "")
    rows = ""
    if q:
        r = g("GET", f"/me/messages?$search=%22{requests.utils.quote(q)}%22"
              "&$select=subject,from,receivedDateTime,isRead&$top=50&$orderby=receivedDateTime desc", t).json()
        if "value" not in r:
            # fallback: search query param ($search not supported everywhere)
            r = g("GET", f"/me/messages?$filter=contains(subject,'{q}')&$top=50&$orderby=receivedDateTime desc", t).json()
        for m in r.get("value", []):
            nm = (m.get("from") or {}).get("emailAddress", {}).get("name", "(unknown)")
            rows += f"<div class=msgrow onclick=\"location='/view/{m['id']}'\">"
            rows += f"<div class=from>{nm}</div><div class=subj>{m.get('subject') or '(no subject)'}</div>"
            rows += f"<div class=date>{m['receivedDateTime'][:16].replace('T',' ')}</div></div>"
    c = f"""<div class=wrap><div class=list style='max-width:900px;margin:auto'>
    <form class=searchbar method=get action=/search>
    <input name=q value="{q}" placeholder="Search all mail..."><button class=btn>Search</button></form>
    {rows if rows else '<p style="padding:15px">No results.</p>' if q else '<p style="padding:15px">Type above to search the entire mailbox.</p>'}
    </div></div>"""
    return page(c, active="search")

@app.route("/rules", methods=["GET", "POST"])
def rules():
    t = tok()
    if not t: return login_page()
    msg = ""
    if request.method == "POST":
        sender = request.form["sender"].lower()
        act = request.form["action"]
        fwd = request.form.get("fwdto", "")
        rul = {"displayName": f"Rule-{sender[:15]}",
            "conditions": {"sentTo": []}, "actions": {}}
        if act == "forward":
            rul["actions"] = {"forwardTo": [{"emailAddress": {"address": fwd}}]}
        else:
            rul["actions"] = {"moveToFolder": "deleteditems"}
        r = g("POST", "/me/mailFolders/inbox/messageRules", t, json=rul)
        msg = "✅ Rule created." if r.status_code in (200, 201) else f"❌ {r.text[:200]}"
    # list existing rules
    r = g("GET", "/me/mailFolders/inbox/messageRules", t).json()
    lst = ""
    for x in r.get("value", []):
        act = "Forward" if x.get("actions", {}).get("forwardTo") else "Delete/Move"
        lst += f"<div class=msgrow><div class=subj>{x['displayName']} — {act}</div>"
        lst += f"<div><a class='btn gray' href='/delrule/{x['id']}'>Delete</a></div></div>"
    c = f"""<div class=box><h2>Inbox Rules</h2><p>{msg}</p>
    <form method=post>
    <label>Sender address</label><input name=sender placeholder="sender@domain.com">
    <label>Action</label><select name=action><option value=forward>Forward</option><option value=delete>Delete</option></select>
    <label>Forward to (if forwarding)</label><input name=fwdto placeholder="you@yourmail.com">
    <br><button class=btn>Create rule</button></form>
    <h3>Active rules</h3>{lst or '<p>No rules.</p>'}</div>"""
    return page(c)

@app.route("/delrule/<rid>")
def delrule(rid):
    t = tok()
    if t: g("DELETE", f"/me/mailFolders/inbox/messageRules/{rid}", t)
    return redirect("/rules")

@app.route("/settings", methods=["GET", "POST"])
def settings():
    t = tok()
    if not t: return login_page()
    me = g("GET", "/me?$select=displayName,mail,userPrincipalName", t).json()
    msg = ""
    if request.method == "POST":
        session["theme"] = "dark" if request.form.get("theme") == "dark" else "light"
        session["per_page"] = max(10, min(100, int(request.form.get("per_page", 25))))
        if request.form.get("dispname"):
            rr = g("PATCH", "/me", t, json={"displayName": request.form["dispname"]})
            msg = "✅ Settings saved." if rr.status_code == 204 else f"❌ {rr.text[:150]}"
        else:
            msg = "✅ Settings saved."
    c = f"""<div class=box><h2>⚙️ Settings</h2><p>{msg}</p>
    <p><b>Account:</b> {me.get('mail') or me.get('userPrincipalName')}<br>
    <b>Name:</b> {me.get('displayName')}</p>
    <form method=post>
    <label>Display name (changes it on the mailbox at Microsoft)</label>
    <input name=dispname value="{me.get('displayName','')}">
    <label>Emails per page</label>
    <select name=per_page><option>{session.get('per_page',25)}</option><option>10</option><option>25</option><option>50</option><option>100</option></select>
    <label>Theme</label>
    <select name=theme><option value=light>Light</option><option value=dark {'selected' if session.get('theme')=='dark' else ''}>Dark</option></select>
    <br><br><button class=btn>Save settings</button></form></div>"""
    return page(c, active="settings")

def login_page():
    c = """<div class=box><h2>Open mailbox</h2>
    <form method=post action=/login>
    <label>Paste refresh_token</label><textarea name=rt rows=4></textarea>
    <br><br><button class=btn>Open mailbox</button></form></div>"""
    return page(c)

@app.route("/login", methods=["POST"])
def login():
    session["rt"] = request.form["rt"].strip()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
