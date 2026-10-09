"""Original-byte validation before any decoder is invoked."""
import hashlib
import struct
import zlib

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 8_000_000


class MediaError(ValueError):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def validate(data, mime):
    if not data:
        raise MediaError("INVALID_MEDIA")
    if len(data) > MAX_BYTES:
        raise MediaError("RESOURCE_LIMIT", 413)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        expected, fmt = "image/png", "PNG"
        pos, ended, chunks = 8, False, 0
        while pos + 12 <= len(data):
            length = struct.unpack_from(">I", data, pos)[0]
            tag = data[pos + 4:pos + 8]
            end = pos + 12 + length
            if end > len(data) or chunks > 2048:
                raise MediaError("INVALID_MEDIA")
            if zlib.crc32(data[pos + 4:end - 4]) & 0xffffffff != struct.unpack_from(">I", data, end - 4)[0]:
                raise MediaError("INVALID_MEDIA")
            if chunks == 0 and (tag != b"IHDR" or length != 13):
                raise MediaError("INVALID_MEDIA")
            if tag == b"acTL":
                raise MediaError("UNSUPPORTED_FORMAT", 415)
            pos, chunks = end, chunks + 1
            if tag == b"IEND":
                ended = length == 0 and pos == len(data)
                break
        if not ended:
            raise MediaError("INVALID_MEDIA")
    elif data.startswith(b"\xff\xd8\xff"):
        expected, fmt = "image/jpeg", "JPEG"
        # Walk length-delimited segments and entropy-coded scans. Searching for
        # EOI alone would mistake marker bytes in legitimate EXIF for an ending.
        pos, in_scan, ended = 2, False, False
        while pos < len(data):
            if in_scan:
                next_marker = data.find(b"\xff", pos)
                if next_marker < 0 or next_marker + 1 >= len(data):
                    break
                pos = next_marker
            if data[pos] != 255:
                break
            while pos < len(data) and data[pos] == 255:
                pos += 1
            if pos >= len(data):
                break
            marker = data[pos]
            pos += 1
            if in_scan and (marker == 0 or 0xd0 <= marker <= 0xd7):
                continue
            if marker == 0xd9:
                ended = pos == len(data)
                break
            in_scan = False
            if marker in (0x00, 0xd8) or pos + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, pos)[0]
            if length < 2 or pos + length > len(data):
                break
            pos += length
            in_scan = marker == 0xda
        if not ended:
            raise MediaError("INVALID_MEDIA")
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        expected, fmt = "image/webp", "WEBP"
        if len(data) < 20 or struct.unpack_from("<I", data, 4)[0] + 8 != len(data):
            raise MediaError("INVALID_MEDIA")
        pos, chunks = 12, 0
        allowed = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ICCP", b"EXIF", b"XMP "}
        while pos + 8 <= len(data):
            tag, length = data[pos:pos + 4], struct.unpack_from("<I", data, pos + 4)[0]
            end = pos + 8 + length + length % 2
            if tag not in allowed or end > len(data) or chunks >= 256:
                raise MediaError("UNSUPPORTED_FORMAT", 415)
            pos, chunks = end, chunks + 1
        if pos != len(data):
            raise MediaError("INVALID_MEDIA")
    else:
        raise MediaError("UNSUPPORTED_FORMAT", 415)
    if mime != expected:
        raise MediaError("MAGIC_BYTES_MISMATCH", 415)
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mime": expected, "format": fmt}
