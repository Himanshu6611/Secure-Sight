"""Inspect containers without extracting paths, macros or executing content."""
import base64
import hashlib
import io
import re
import zipfile
from pathlib import PurePosixPath

EXECUTABLES = {"exe", "dll", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "msi", "hta", "lnk", "jar"}


def inspect(attachment):
    data = base64.b64decode(attachment.pop("_data"), validate=True)
    original_name = attachment.pop("filename")
    name = original_name.replace("\\", "/").rsplit("/", 1)[-1]
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    flags, urls = [], []
    if original_name != name or any(c in original_name for c in "\x00\r\n"):
        flags.append("UNSAFE_FILENAME")
    if len(name.split(".")) > 2 and extension in EXECUTABLES:
        flags.append("DOUBLE_EXTENSION_EXECUTABLE")
    magic = "PNG" if data.startswith(b"\x89PNG\r\n\x1a\n") else "JPEG" if data.startswith(b"\xff\xd8\xff") else "WEBP" if data[:4] == b"RIFF" and data[8:12] == b"WEBP" else "EXECUTABLE" if data.startswith((b"MZ", b"\x7fELF")) else "ZIP" if data.startswith(b"PK\x03\x04") else "PDF" if data.startswith(b"%PDF-") else "OLE" if data.startswith(b"\xd0\xcf\x11\xe0") else "UNKNOWN"
    if extension in EXECUTABLES or magic == "EXECUTABLE":
        flags.append("EXECUTABLE_ATTACHMENT")
    if extension in {"docm", "xlsm", "pptm"} or magic == "OLE":
        flags.append("MACRO_CAPABLE_ATTACHMENT")
    expected = {"PNG": ({"png"}, "image/png"), "JPEG": ({"jpg", "jpeg"}, "image/jpeg"), "WEBP": ({"webp"}, "image/webp"), "PDF": ({"pdf"}, "application/pdf")}
    if magic in expected and (extension not in expected[magic][0] or attachment["mime"] != expected[magic][1]):
        flags.append("ATTACHMENT_TYPE_MISMATCH")
    archive = {"status": "NOT_APPLICABLE"}
    if magic == "ZIP":
        archive = {"status": "ANALYZED", "entries": 0, "expanded_bytes": 0, "extracted": False}
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as stream:
                entries = stream.infolist()
                if len(entries) > 64:
                    raise ValueError("Archive entry limit")
                for entry in entries:
                    archive["entries"] += 1
                    archive["expanded_bytes"] += entry.file_size
                    path = PurePosixPath(entry.filename.replace("\\", "/"))
                    if path.is_absolute() or ".." in path.parts or ":" in entry.filename:
                        flags.append("ARCHIVE_PATH_TRAVERSAL")
                    if entry.file_size > 1024 * 1024 or archive["expanded_bytes"] > 2 * 1024 * 1024 or entry.file_size / max(1, entry.compress_size) > 100:
                        flags.append("ARCHIVE_RESOURCE_LIMIT")
                        break
                    if entry.flag_bits & 1:
                        flags.append("ENCRYPTED_ARCHIVE_UNINSPECTED")
                        continue
                    suffix = path.suffix.lower().lstrip(".")
                    if suffix in {"zip", "rar", "7z", "gz", "tar", "eml"}:
                        flags.append("NESTED_ARCHIVE_UNINSPECTED")
                    if suffix in EXECUTABLES:
                        flags.append("EXECUTABLE_ARCHIVE_MEMBER")
                    if "vbaproject" in entry.filename.casefold():
                        flags.append("MACRO_ATTACHMENT")
                    if suffix in {"txt", "rels", "xml"} and entry.file_size <= 65536:
                        text = stream.read(entry).decode("utf-8", "replace")
                        urls.extend(re.findall(r"https?://[^\s<>\"']+", text)[:16])
        except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
            archive["status"] = "PARTIAL"
            flags.append("ARCHIVE_ANALYSIS_FAILED")
    elif attachment["mime"] == "text/plain" and len(data) <= 65536:
        urls = re.findall(r"https?://[^\s<>\"']+", data.decode("utf-8", "replace"))[:16]
    if magic in {"PDF", "OLE", "UNKNOWN"}:
        flags.append("ATTACHMENT_CONTENT_UNSUPPORTED")
    if any(flag in flags for flag in {"ARCHIVE_RESOURCE_LIMIT", "NESTED_ARCHIVE_UNINSPECTED", "ENCRYPTED_ARCHIVE_UNINSPECTED", "ARCHIVE_PATH_TRAVERSAL"}):
        archive["status"] = "PARTIAL"
    attachment.update(filename=name[:128], filename_sha256=hashlib.sha256(original_name.encode()).hexdigest(),
        magic=magic, indicators=sorted(set(flags)), archive=archive, status="PARTIAL" if flags else "ANALYZED",
        executed=False, _urls=list(dict.fromkeys(urls))[:16])
    return attachment, data
