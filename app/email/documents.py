"""Extract bounded, passive text from common email-export documents."""
import io
import zipfile
from defusedxml import ElementTree
from pypdf import PdfReader
from .parser import EmailError, MAX_EMAIL_BYTES

MAX_EXTRACTED_TEXT = 64 * 1024
MAX_DOCX_EXPANDED = 12 * 1024 * 1024


def _pdf(raw):
    if not raw.startswith(b"%PDF-"):
        raise EmailError("DOCUMENT_TYPE_MISMATCH", 415)
    try:
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise EmailError("ENCRYPTED_DOCUMENT_UNSUPPORTED", 422)
        if len(reader.pages) > 20:
            raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
        parts = []
        size = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            size += len(text)
            if size > MAX_EXTRACTED_TEXT:
                raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
            parts.append(text)
        return "\n".join(parts)
    except EmailError:
        raise
    except Exception:
        raise EmailError("DOCUMENT_PARSE_FAILED", 422) from None


def _docx(raw):
    if not raw.startswith(b"PK\x03\x04"):
        raise EmailError("DOCUMENT_TYPE_MISMATCH", 415)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > 256 or sum(item.file_size for item in entries) > MAX_DOCX_EXPANDED:
                raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
            if any(item.file_size / max(1, item.compress_size) > 100 for item in entries):
                raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
            names = {item.filename for item in entries}
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise EmailError("DOCUMENT_TYPE_MISMATCH", 415)
            xml = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml)
        text = " ".join(value for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "t" for value in [node.text or ""])
        if len(text) > MAX_EXTRACTED_TEXT:
            raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
        return text
    except EmailError:
        raise
    except (zipfile.BadZipFile, KeyError, ElementTree.ParseError, ValueError, OSError):
        raise EmailError("DOCUMENT_PARSE_FAILED", 422) from None


def _xml(raw):
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailError("EMAIL_RESOURCE_LIMIT", 413)
    try:
        root = ElementTree.fromstring(raw)
        values = []
        size = 0
        for node in root.iter():
            if node.text and node.text.strip():
                value = node.text.strip()
                values.append(value)
                size += len(value)
            for attribute in node.attrib.values():
                if attribute.strip():
                    value = attribute.strip()
                    values.append(value)
                    size += len(value)
            if size > MAX_EXTRACTED_TEXT:
                raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
        return "\n".join(values)
    except EmailError:
        raise
    except (ElementTree.ParseError, ValueError):
        raise EmailError("DOCUMENT_PARSE_FAILED", 422) from None


def extract(raw, document_format):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EMAIL_BYTES:
        raise EmailError("EMAIL_RESOURCE_LIMIT" if raw else "INVALID_EMAIL", 413 if raw else 400)
    extractors = {"pdf": _pdf, "docx": _docx, "xml": _xml}
    extractor = extractors.get(document_format)
    if extractor is None:
        raise EmailError("UNSUPPORTED_EMAIL_FORMAT", 415)
    text = extractor(raw).strip()
    if not text:
        raise EmailError("DOCUMENT_TEXT_UNAVAILABLE", 422)
    if len(text.encode("utf-8")) > MAX_EXTRACTED_TEXT:
        raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
    return text
