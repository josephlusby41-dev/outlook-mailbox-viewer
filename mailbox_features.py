from base64 import b64encode
from io import BytesIO
from pathlib import PurePath
import re
from urllib.parse import quote
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from flask import jsonify, request


def register_mailbox_features(app, graph, error):
    def attachment_path(message_id, attachment_id=None):
        path = "/me/messages/" + quote(message_id, safe="") + "/attachments"
        if attachment_id is not None:
            path += "/" + quote(attachment_id, safe="")
        return path

    @app.post("/api/features/graph")
    def feature_graph():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise error("Expected a JSON object.")

        method, path = body.get("method"), body.get("path")
        if not isinstance(path, str):
            raise error("Invalid mailbox path.")

        patterns = {
            "GET": [
                r"/me/messages/[^/]+(?:/attachments)?",
                r"/me/(?:mailboxSettings|calendarView|contacts|outlook/masterCategories)",
                r"/me/todo/lists(?:/[^/]+/tasks)?",
                r"/me/mailFolders/inbox/messageRules/[^/]+",
            ],
            "POST": [
                r"/me/messages(?:/[^/]+/(?:copy|move|send))?",
                r"/me/mailFolders(?:/[^/]+/(?:childFolders|move))?",
                r"/me/(?:events|contacts)",
                r"/me/todo/lists/[^/]+/tasks",
            ],
            "PATCH": [
                r"/me/(?:messages|mailFolders|events|contacts)/[^/]+",
                r"/me/mailboxSettings",
                r"/me/mailFolders/inbox/messageRules/[^/]+",
                r"/me/todo/lists/[^/]+/tasks/[^/]+",
            ],
            "DELETE": [
                r"/me/(?:mailFolders|events|contacts)/[^/]+",
                r"/me/messages/[^/]+/attachments/[^/]+",
                r"/me/todo/lists/[^/]+/tasks/[^/]+",
            ],
        }

        if not isinstance(method, str) or not any(
            re.fullmatch(pattern, path) for pattern in patterns.get(method, ())
        ):
            raise error("This action is unavailable.")

        return jsonify(graph(method, path, body.get("query"), body.get("payload")))

    @app.post("/api/features/attachments/<message_id>")
    def feature_upload(message_id):
        file = request.files.get("file")
        if not file or not file.filename:
            raise error("Choose a file.")

        data = file.stream.read(3_000_000)
        if not data or len(data) >= 3_000_000:
            raise error("Choose a nonempty file smaller than 3 MB.")

        result = graph("POST", attachment_path(message_id), payload={
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": PurePath(file.filename.replace("\\", "/")).name[:255],
            "contentType": file.mimetype or "application/octet-stream",
            "contentBytes": b64encode(data).decode("ascii"),
        })
        return jsonify(id=result.get("id"), name=result.get("name"))

    @app.post("/api/features/preview")
    def feature_preview():
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            raise error("Expected a JSON object.")

        mid, aid = body.get("message"), body.get("attachment")
        if not all(isinstance(value, str) and value for value in (mid, aid)):
            raise error("Choose an attachment.")

        path = attachment_path(mid, aid)
        metadata = graph("GET", path, {"$select": "name,size,contentType"})
        if not isinstance(metadata.get("size"), int) or metadata["size"] > 15_000_000:
            raise error("Preview is limited to 15 MB. Use Download for this file.", 413)

        content = graph("GET", path + "/$value", binary=True)
        if isinstance(content, tuple):
            content = content[0]
        if len(content) > 15_000_000:
            raise error("Preview is limited to 15 MB. Use Download for this file.", 413)

        name = str(metadata.get("name") or "").lower()
        mime = None

        if content.startswith(b"%PDF-"):
            mime = "application/pdf"
        elif content.startswith(b"\x89PNG\r\n\x1a\n"):
            mime = "image/png"
        elif content.startswith(b"\xff\xd8\xff"):
            mime = "image/jpeg"
        elif content.startswith((b"GIF87a", b"GIF89a")):
            mime = "image/gif"
        elif content.startswith(b"RIFF") and content[8:12] == b"WEBP":
            mime = "image/webp"
        elif name.endswith((".txt", ".csv", ".log")):
            return jsonify(text=content[:250_000].decode("utf-8-sig", errors="replace"))
        elif name.endswith(".docx"):
            try:
                with ZipFile(BytesIO(content)) as archive:
                    entry = archive.getinfo("word/document.xml")
                    if entry.file_size > 2_000_000:
                        raise error("This document is too large to preview.", 413)
                    xml = archive.read(entry)

                if b"<!" in xml or b"\x00" in xml:
                    raise ValueError

                root = ElementTree.fromstring(xml)
                namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
                paragraphs = [
                    "".join(node.text or "" for node in paragraph.iter(namespace + "t"))
                    for paragraph in root.iter(namespace + "p")
                ]
                return jsonify(text="\n".join(paragraphs)[:250_000])
            except (BadZipFile, KeyError, ValueError, ElementTree.ParseError, RuntimeError):
                raise error("This Word document could not be previewed. Use Download.", 415) from None

        if not mime:
            raise error("Preview is unavailable for this file type. Use Download.", 415)

        return app.response_class(content, content_type=mime)
