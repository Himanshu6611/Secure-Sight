"""Extract bounded, passive text from common email-export documents."""
import io
import os
import zipfile
from defusedxml import ElementTree
from pypdf import PdfReader
from .parser import EmailError, MAX_EMAIL_BYTES

MAX_EXTRACTED_TEXT = 64 * 1024
MAX_DOCX_EXPANDED = 12 * 1024 * 1024
PDF_OCR_MAX_DIMENSION = 2000
PDF_OCR_TIMEOUT_SECONDS = 2.0


def _open_pdf_for_ocr(raw):
    try:
        import pypdfium2 as pdfium
        return pdfium.PdfDocument(raw)
    except ImportError:
        raise EmailError("DOCUMENT_OCR_UNAVAILABLE", 503) from None
    except Exception:
        raise EmailError("DOCUMENT_OCR_FAILED", 422) from None


def _ocr_pdf_page(document, page_number):
    """OCR one textless PDF page in the already isolated document worker."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        raise EmailError("DOCUMENT_OCR_UNAVAILABLE", 503) from None

    page = bitmap = image = None
    try:
        page = document[page_number]
        width, height = page.get_size()
        if not width or not height or width > 200_000 or height > 200_000:
            raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
        scale = min(1.5, PDF_OCR_MAX_DIMENSION / max(width, height))
        bitmap = page.render(scale=scale, rotation=0)
        image = bitmap.to_pil().convert("L")
        if image.width * image.height > PDF_OCR_MAX_DIMENSION ** 2:
            raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
        command = os.environ.get("TESSERACT_CMD") or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.path.isfile(command):
            pytesseract.pytesseract.tesseract_cmd = command
        try:
            return pytesseract.image_to_string(
                image, lang="eng+hin", config="--psm 6", timeout=PDF_OCR_TIMEOUT_SECONDS
            )
        except RuntimeError as exc:
            if "timeout" in str(exc).lower():
                raise EmailError("DOCUMENT_OCR_TIMEOUT", 422) from None
            raise EmailError("DOCUMENT_OCR_FAILED", 422) from None
        except Exception:
            raise EmailError("DOCUMENT_OCR_FAILED", 422) from None
    except EmailError:
        raise
    except Exception:
        raise EmailError("DOCUMENT_OCR_FAILED", 422) from None
    finally:
        if image is not None:
            image.close()
        if bitmap is not None:
            bitmap.close()
        if page is not None:
            page.close()


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
        ocr_document = None
        try:
            for page_number, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if not text.strip():
                    if ocr_document is None:
                        ocr_document = _open_pdf_for_ocr(raw)
                    text = _ocr_pdf_page(ocr_document, page_number)
                size += len(text)
                if size > MAX_EXTRACTED_TEXT:
                    raise EmailError("DOCUMENT_RESOURCE_LIMIT", 413)
                parts.append(text)
        finally:
            if ocr_document is not None:
                ocr_document.close()
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
