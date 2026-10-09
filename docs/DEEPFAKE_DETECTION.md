# Deepfake detection

`MediaDetectionModel` defines the media adapter contract. The installed `UnavailableMediaModel` returns MODEL_UNAVAILABLE, null synthetic/manipulation/face probabilities, null model name/version/confidence, empty individual outputs and UNAVAILABLE agreement. No media model weights or evaluated ensemble are installed.

The previous zero-shot CLIP labels and hardcoded 0.5 fallback were removed. CLIP similarity cannot be represented as an evaluated deepfake probability. No face-identification service, biometric retention, or claimed 100% detection exists.

Deployment requires verified licensed local model artifacts, real held-out evaluations and calibration before enabling a probability-producing adapter. This phase does not retrain or alter the existing URL model.
