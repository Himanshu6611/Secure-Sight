# Image metadata and identity

SHA256 identifies exact original bytes before normalization. A 64-bit dHash and 63-bit DCT pHash summarize normalized grayscale content; their algorithm identifiers are returned. These hashes are evidence identity and approximate similarity tools, not authenticity proofs. Different metadata may change SHA256 while perceptual similarity remains high.

Metadata includes decoded dimensions, color mode, safe orientation and presence flags for EXIF, GPS, camera, software, timestamps, ICC and XMP. GPS coordinates, camera serials, device names, author strings and raw XML/ICC are not returned. EXIF orientation is applied for OCR/QR/hash normalization. XMP is never passed to an XML/entity parser. Missing EXIF adds no risk.

Detailed metadata inconsistency/time anomaly detection and ICC color-management interpretation remain unavailable. Parse failures never establish safety.
