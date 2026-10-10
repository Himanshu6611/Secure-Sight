"""Decoder, measured image properties, real OCR and QR extraction inside a worker."""
import hashlib
import io
import os
import re
import warnings
from .intake import MediaError, MAX_PIXELS
from .models import ExperimentalAIOriginModel
from .provenance import analyze as provenance


def process(data, artifact, language="eng"):
    import numpy as np
    from PIL import Image, ImageOps, ImageFilter, ImageChops
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(data)) as original:
                width, height = original.size
                if min(width, height) < 2 or max(width, height) > 4096 or width * height > MAX_PIXELS:
                    raise MediaError("RESOURCE_LIMIT")
                if original.format != artifact["format"] or getattr(original, "n_frames", 1) != 1:
                    raise MediaError("UNSUPPORTED_FORMAT", 415)
                original.verify()
            with Image.open(io.BytesIO(data)) as original:
                exif = original.getexif()
                metadata = {"status": "ANALYZED", "width": width, "height": height,
                    "orientation": exif.get(274) if exif.get(274) in range(1, 9) else None,
                    "color_space": original.mode, "exif_present": bool(exif),
                    "gps_present": 34853 in exif, "software_present": 305 in exif,
                    "camera_present": 271 in exif or 272 in exif,
                    "timestamp_present": 306 in exif or 36867 in exif,
                    "icc_present": bool(original.info.get("icc_profile")),
                    "xmp_present": any("xmp" in str(k).lower() for k in original.info),
                    "sensitive_values_redacted": True, "metadata_is_authenticity_proof": False}
                quantization = getattr(original, "quantization", None)
                image = ImageOps.exif_transpose(original).convert("RGB")
        except MediaError:
            raise
        except (Image.DecompressionBombWarning, Image.DecompressionBombError):
            raise MediaError("RESOURCE_LIMIT") from None
        except Exception:
            raise MediaError("IMAGE_DECODE_FAILED") from None
    gray = image.convert("L")
    small = np.asarray(gray.resize((9, 8)), dtype=np.int16)
    dhash = sum(int(x) << i for i, x in enumerate((small[:, 1:] > small[:, :-1]).flatten()))
    from scipy.fft import dctn
    coeff = dctn(np.asarray(gray.resize((32, 32)), dtype=float), norm="ortho")[:8, :8].flatten()[1:]
    phash = sum(int(x) << i for i, x in enumerate(coeff > np.median(coeff)))
    artifact.update({"dhash": f"{dhash:016x}", "phash": f"{phash:016x}", "hash_algorithm": "dhash9x8/phash-DCT32-63bit-v1"})
    preview = gray.copy()
    preview.thumbnail((512, 512))
    arr = np.asarray(preview, dtype=float)
    gradient = float(np.mean(np.abs(np.diff(arr, axis=0))))
    quality = {"status": "INSUFFICIENT_QUALITY" if min(width, height) < 64 or gradient < .3 else "ANALYZED",
               "minimum_dimension": min(width, height), "mean_vertical_gradient": round(gradient, 4),
               "confidence": None, "calibrated": False}
    stream = io.BytesIO()
    image.save(stream, "JPEG", quality=90)
    with Image.open(io.BytesIO(stream.getvalue())) as compressed:
        difference = np.asarray(ImageChops.difference(image, compressed.convert("RGB")), dtype=float)
    residual = np.asarray(preview, dtype=float) - np.asarray(preview.filter(ImageFilter.MedianFilter(3)), dtype=float)
    forensics = {"status": "ANALYZED", "confidence": None, "calibrated": False,
        "recompression_mean_absolute_error": round(float(difference.mean()), 4),
        "median_residual_variance": round(float(residual.var()), 4),
        "jpeg_quantization_tables": len(quantization or {}),
        "copy_move_status": "MODEL_UNAVAILABLE", "face_analysis_status": "MODEL_UNAVAILABLE",
        "resampling_status": "MODEL_UNAVAILABLE", "lighting_status": "MODEL_UNAVAILABLE",
        "interpretation": "Measured properties only; no validated manipulation probability."}
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2(arr - arr.mean()))) ** 2
    yy, xx = np.indices(arr.shape)
    radius = np.sqrt(((yy - arr.shape[0] / 2) / arr.shape[0]) ** 2 + ((xx - arr.shape[1] / 2) / arr.shape[1]) ** 2)
    total_energy = float(spectrum.sum())
    forensics["high_frequency_energy_fraction"] = round(float(spectrum[radius > .3].sum()) / total_energy, 6) if total_energy else None
    forensics["edge_gradient_mean"] = round(gradient, 4)
    patches = [arr[y:y + 32, x:x + 32] for y in range(0, arr.shape[0] - 31, 32) for x in range(0, arr.shape[1] - 31, 32)]
    forensics["local_texture_variances"] = [round(float(p.var()), 3) for p in patches[:64]]
    ocr = {"status": "OCR_FAILED", "text": "", "words": [], "language": language, "source_sha256": artifact["sha256"]}
    try:
        import pytesseract
        command = os.environ.get("TESSERACT_CMD") or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.path.isfile(command):
            pytesseract.pytesseract.tesseract_cmd = command
        extracted = pytesseract.image_to_data(image, lang=language, config="--psm 11", output_type=pytesseract.Output.DICT, timeout=4)
        words = []
        for i, text in enumerate(extracted["text"]):
            text = "".join(c for c in text[:128] if c.isprintable())
            confidence = float(extracted["conf"][i])
            if text and confidence >= 0 and len(words) < 256:
                words.append({"text": text, "confidence": round(confidence / 100, 4),
                    "bbox": [int(extracted[k][i]) for k in ("left", "top", "width", "height")]})
        ocr.update(status="ANALYZED", words=words, text=" ".join(w["text"] for w in words)[:8192])
    except Exception:
        ocr["error_code"] = "OCR_FAILED"
    qr = {"status": "QR_DECODE_FAILED", "items": [], "decoder": "OpenCV QRCodeDetector"}
    try:
        import cv2
        cv2.setNumThreads(1)
        detector = cv2.QRCodeDetector()
        matrix = np.asarray(image)
        matrix = cv2.cvtColor(matrix, cv2.COLOR_RGB2BGR)
        found, values, points, _ = detector.detectAndDecodeMulti(matrix)
        if not found:
            value, point, _ = detector.detectAndDecode(matrix)
            values, points = ([value], [point]) if value else ([], [])
        for value, point in list(zip(values, points))[:8]:
            if value and len(value) <= 2048:
                qr["items"].append({"payload": value, "payload_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    "type": "URL" if value.lower().startswith(("https://", "http://")) else "TEXT",
                    "location": np.asarray(point).reshape(-1, 2).round(2).tolist(), "confidence": None})
        qr["status"] = "ANALYZED"
    except Exception:
        qr["error_code"] = "QR_DECODE_FAILED"
    urls = re.findall(r"https?://[^\s<>\"']+", ocr["text"], flags=re.I)
    entity_patterns = {
        "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phones": r"(?<!\w)\+?\d[\d ()-]{6,18}\d(?!\w)",
        "amounts": r"(?:[$€£₹]|USD\s|INR\s)\s?\d+(?:[.,]\d+)*",
        "dates": r"\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b",
    }
    ocr["entities"] = {kind: [{"sha256": hashlib.sha256(match.group().encode()).hexdigest(),
                                "text_span": [match.start(), match.end()], "value_redacted": True}
                              for match in list(re.finditer(pattern, ocr["text"], flags=re.I))[:32]]
                       for kind, pattern in entity_patterns.items()}
    ocr["credential_terms"] = sorted(set(re.findall(r"\b(?:password|login|verify|credential|otp)\b", ocr["text"], flags=re.I)))
    urls.extend(item["payload"] for item in qr["items"] if item["type"] == "URL")
    return {"artifact": artifact, "metadata": metadata, "quality": quality, "forensics": forensics,
            "synthetic_media": ExperimentalAIOriginModel().analyze(image, quality), "ocr": ocr, "qr": qr,
            "provenance": provenance(data, artifact["mime"]), "_urls": list(dict.fromkeys(urls))[:8]}
