"""Never render or execute MIME. Preserve identity, bound every decoded part."""
import base64
import hashlib
import re
from email import policy
from email.parser import BytesParser
from .headers import analyze_headers

MAX_EMAIL_BYTES = 2 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 512 * 1024


class EmailError(ValueError):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def parse(raw):
    if not isinstance(raw, bytes) or not raw.strip():
        raise EmailError("INVALID_EMAIL")
    if len(raw) > MAX_EMAIL_BYTES or raw.count(b"\n") > 20000:
        raise EmailError("EMAIL_RESOURCE_LIMIT", 413)
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        header_end = raw.find(b"\n\n")
    structured = header_end >= 0 and b":" in raw[:min(header_end, 1024)]
    if structured and (header_end > 65536 or any(len(line) > 8192 for line in raw[:header_end].splitlines())):
        raise EmailError("HEADER_RESOURCE_LIMIT", 413)
    # Bound structural work before the stdlib constructs the recursive MIME tree.
    # Conservative wire limits also cover nested message/rfc822 (no boundaries).
    if structured and (len(re.findall(br"(?im)^content-type[ \t]*:", raw)) > 32 or
                       sum(line.startswith(b"--") for line in raw.splitlines()) > 96):
        raise EmailError("MIME_RESOURCE_LIMIT", 413)
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw) if structured else BytesParser(policy=policy.default).parsebytes(b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + raw)
    except RecursionError:
        raise EmailError("MIME_RESOURCE_LIMIT", 413) from None
    if len(message.items()) > 128:
        raise EmailError("HEADER_RESOURCE_LIMIT", 413)
    result = {"email_feature_version": "11.0", "parser_version": "11.0",
        "email_id": hashlib.sha256(raw).hexdigest(), "original_bytes": len(raw), "raw_retention": "REQUEST_ONLY",
        "input_kind": "MIME" if structured else "BODY_ONLY", "headers": analyze_headers(message),
        "bodies": [], "attachments": [], "defects": [], "parts": 0}
    total_body, total_attachment = 0, 0
    def visit(part, depth):
        nonlocal total_body, total_attachment
        result["parts"] += 1
        if depth > 8 or result["parts"] > 32:
            raise EmailError("MIME_RESOURCE_LIMIT", 413)
        defects = [type(defect).__name__ for defect in part.defects]
        result["defects"].extend(defects[:8])
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child, depth + 1)
            return
        decoded = part.get_payload(decode=True)
        if decoded is None:
            decoded = str(part.get_payload()).encode("utf-8", "replace")
        result["defects"].extend(type(d).__name__ for d in part.defects if type(d).__name__ not in defects)
        content_type = part.get_content_type()
        filename = part.get_filename()
        is_body = not filename and part.get_content_disposition() != "attachment" and content_type in {"text/plain", "text/html"}
        if is_body:
            total_body += len(decoded)
            if total_body > 65536:
                raise EmailError("BODY_RESOURCE_LIMIT", 413)
            charset = part.get_content_charset() or "utf-8"
            try:
                text = decoded.decode(charset, "replace")
            except (LookupError, UnicodeError):
                text = decoded.decode("utf-8", "replace")
                result["defects"].append("UNKNOWN_CHARSET")
            result["bodies"].append({"type": content_type, "text": text, "charset": charset[:64],
                "sha256": hashlib.sha256(decoded).hexdigest()})
        else:
            total_attachment += len(decoded)
            if len(result["attachments"]) >= 8 or len(decoded) > MAX_ATTACHMENT_BYTES or total_attachment > 1024 * 1024:
                raise EmailError("ATTACHMENT_RESOURCE_LIMIT", 413)
            result["attachments"].append({"filename": (filename or "unnamed")[:256], "mime": content_type,
                "content_id_sha256": hashlib.sha256(str(part.get("Content-ID", "")).encode()).hexdigest(),
                "disposition": part.get_content_disposition(), "bytes": len(decoded),
                "sha256": hashlib.sha256(decoded).hexdigest(), "_data": base64.b64encode(decoded).decode()})
    visit(message, 0)
    result["defects"] = list(dict.fromkeys(result["defects"]))[:32]
    return result
