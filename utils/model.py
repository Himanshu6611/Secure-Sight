#!/usr/bin/env python3
"""
utils/model.py
-------------
Loads the trained voting‑classifier and provides helper methods.
"""

import os
import joblib
import pandas as pd

MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "models", "ensemble.pkl")
)
EMAIL_MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "models", "email_model.pkl")
)

def load_ensemble():
    """Load the persisted voting classifier (joblib)."""
    if not os.path.exists(MODEL_PATH):
        # Return none or raise but let's be safe
        return None
    return joblib.load(MODEL_PATH)

def load_email_model():
    """Load the email phishing classifier."""
    if not os.path.exists(EMAIL_MODEL_PATH):
        return None
    return joblib.load(EMAIL_MODEL_PATH)

def predict_proba(model, features: pd.DataFrame) -> float:
    """
    Return the probability of the **phishing** class (class 1).
    The model is a scikit‑learn VotingClassifier.
    """
    # VotingClassifier’s predict_proba returns (n_samples, n_classes)
    # Ensure order is [0,1] – class 1 is phishing.
    proba = model.predict_proba(features)[:, 1][0]
    return float(proba)

def explain_prediction(url: str, ml_prob: float, risk_score: float) -> dict:
    """
    Small helper to build a human‑readable dict for the UI.
    """
    return {
        "ML probability (phish)": round(ml_prob, 3),
        "Risk score (0‑100)": risk_score,
        "Decision": "Phishing" if (risk_score >= 70 or ml_prob >= 0.85) else "Legitimate"
    }
