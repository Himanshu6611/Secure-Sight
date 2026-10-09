"""Compatibility wrapper for the versioned media service."""
from app.media.service import analyze


def analyze_image(file):
    media = analyze(file)
    return {"media": media, "model_available": False, "risk_score": media["assessment"]["risk_score"],
            "ml_risk": None, "is_ai_generated": None, "confidence": None,
            "signals": [item["id"] for item in media["evidence"]],
            "warning": "The trained model is unavailable; image authenticity is unknown."}
