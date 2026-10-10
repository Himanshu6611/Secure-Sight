"""Optional, dataset-scoped AI-origin estimate; never a deepfake/authenticity proof."""
from abc import ABC, abstractmethod
from functools import lru_cache
import hashlib
import json
from pathlib import Path


class MediaDetectionModel(ABC):
    @abstractmethod
    def analyze(self, image, quality):
        """Return actual model outputs, provenance and calibrated confidence if available."""


class UnavailableMediaModel(MediaDetectionModel):
    def analyze(self, image, quality):
        return {"synthetic_probability": None, "manipulation_probability": None,
                "face_manipulation_probability": None, "confidence": None,
                "model_name": None, "model_version": None, "analysis_status": "MODEL_UNAVAILABLE",
                "outputs": [], "agreement": "UNAVAILABLE", "calibrated": False}


MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "image_origin"
MODEL_PATH = MODEL_DIR / "image_origin_cnn.onnx"
EVALUATION_PATH = MODEL_DIR / "evaluation.json"


@lru_cache(maxsize=1)
def _session():
    """Load only the fixed, repository-shipped ONNX model in the isolated worker."""
    import onnxruntime as ort
    metadata = json.loads(EVALUATION_PATH.read_text(encoding="utf-8"))
    digest = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    if digest != metadata.get("model_sha256"):
        raise ValueError("model checksum mismatch")
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    session = ort.InferenceSession(str(MODEL_PATH), sess_options=options,
                                   providers=["CPUExecutionProvider"])
    return session, metadata


class ExperimentalAIOriginModel(MediaDetectionModel):
    """Compact CNN trained for AI-generated-vs-authentic image pattern screening."""

    def analyze(self, image, quality):
        base = {"synthetic_probability": None, "manipulation_probability": None,
                "face_manipulation_probability": None, "confidence": None,
                "model_name": "SecureSight experimental AI-origin CNN",
                "model_version": "2026.10.10", "analysis_status": "MODEL_UNAVAILABLE",
                "outputs": [], "agreement": "UNAVAILABLE", "calibrated": False,
                "score_semantics": "UNCALIBRATED_MODEL_SCORE",
                "scope": "AI-generated image patterns; not face deepfakes or image authenticity"}
        if quality.get("status") != "ANALYZED":
            base.update(analysis_status="INSUFFICIENT_QUALITY", reason="IMAGE_QUALITY")
            return base
        try:
            import numpy as np
            from PIL import Image, ImageOps
            session, metadata = _session()
            fitted = ImageOps.fit(image.convert("RGB"), (96, 96),
                                  method=Image.Resampling.BICUBIC, centering=(0.5, 0.5))
            tensor = np.asarray(fitted, dtype=np.float32) / 255.0
            tensor = np.transpose(tensor, (2, 0, 1))[None, ...].copy()
            logit = float(session.run(["logit"], {"image": tensor})[0][0])
            score = 1.0 / (1.0 + np.exp(-np.clip(logit, -80, 80)))
            threshold = float(metadata["decision_threshold"])
            classification = "AI_GENERATED_PATTERN" if score >= threshold else "NOT_FLAGGED_AS_AI"
            base.update(analysis_status="EXPERIMENTAL_ESTIMATE", model_score=round(float(score), 6),
                classification=classification, decision_threshold=threshold,
                test_metrics=metadata.get("test_at_selected_threshold", {}),
                model_sha256=metadata["model_sha256"], calibrated=False,
                outputs=[{"kind": "AI_ORIGIN_PATTERN", "score": round(float(score), 6),
                          "classification": classification}], agreement="SINGLE_MODEL")
            return base
        except Exception as exc:
            # A missing or damaged optional artifact must not fail image intake.
            # Return only the exception class for server-side diagnosis; exception
            # messages can contain paths or environment details and are not exposed.
            base["diagnostic_code"] = type(exc).__name__[:64]
            return base
