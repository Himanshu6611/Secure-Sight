# ml/calibration.py
"""
ml/calibration.py
------------------
Probability Calibration Engine for SecureSight Phase 5.
Applies Isotonic Regression or Platt Scaling (Sigmoid) to turn raw model probabilities
into well-calibrated confidence scores evaluated on validation data.
"""

from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV


def calibrate_classifier(
    estimator: Any,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    method: str = "isotonic"
) -> Tuple[CalibratedClassifierCV, Dict[str, Any]]:
    """
    Fit probability calibrator on validation data.
    Methods supported: 'isotonic' or 'sigmoid' (Platt scaling).
    """
    calibrated = CalibratedClassifierCV(estimator=estimator, method=method, cv="prefit")
    calibrated.fit(X_val, y_val)

    report = {
        "calibration_method": method,
        "validation_samples": len(X_val),
    }

    return calibrated, report
