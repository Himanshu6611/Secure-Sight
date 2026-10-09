"""Adapters must supply independently evaluated models; CLIP is not a deepfake detector."""
from abc import ABC, abstractmethod


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
