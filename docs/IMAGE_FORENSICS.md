# Image forensics

Measured features: JPEG quantization-table count; JPEG-quality-90 recompression mean absolute error; median-filter residual variance; high-frequency FFT energy fraction; vertical edge gradient; and bounded local texture variances. FFT/texture operate on at most 512×512 pixels. These are reproducible numeric observations, not calibrated anomaly classifiers. Detector confidence is null, and no forensic values contribute risk points.

Copy-move, facial manipulation, resampling classification, shadow/lighting consistency and a validated double-compression detector remain unavailable. Recompression is not a validated double-JPEG test. Normal compression, missing EXIF, scanner text, QR graphics and editing software are not treated as phishing or proof of fabrication.
