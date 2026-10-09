# QR intelligence

OpenCV 4.11 `QRCodeDetector` performs multi-code decoding with single-code fallback. At most eight bounded payloads are retained internally. Results include type, payload SHA256, quadrilateral location and null decoder confidence (OpenCV does not supply a probability). Text payloads are redacted; public URL displays show hostname only.

Decoded HTTP(S) destinations are normalized and validated by Phase 2, then one destination enters the complete shared Phase 2–9 scanner in a killable worker. Private addresses, credentials, nonstandard ports and malformed URLs are rejected. DNS rebinding and redirect safety reuse the existing scanner. One normalized destination prevents duplicate scans and bounded resource use; additional destinations are explicitly reported as limited, not safe. QR presence adds zero risk points.

Valid, private, duplicate and real multi-code fixtures are tested. Results are not guaranteed for every QR size, error-correction level, angle or damaged symbol.
