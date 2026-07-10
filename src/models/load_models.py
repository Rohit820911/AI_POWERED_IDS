"""
load_models.py
--------------
Loads all models once when Flask starts.
Every other module imports from here.

Training facts confirmed from notebook:
  - RF  : trained on raw 40 selected_features (NO scaling)
  - XGB : trained on raw 40 selected_features (NO scaling)
  - ISO : trained on scaled top15_features only (RobustScaler on BENIGN data)
"""

import os
import joblib
from xgboost import XGBClassifier

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models")

def load_all_models() -> dict:
    """
    Loads every artifact from models/ and returns them in a dict.
    Called once at Flask startup. Pass the dict around instead of globals.
    """
    print("[load_models] Loading artifacts...")

    xgb = XGBClassifier()
    xgb.load_model(os.path.join(MODELS_DIR, "xgboost.json"))

    models = {
        # Classifiers
        "rf":  joblib.load(os.path.join(MODELS_DIR, "random_forest.pkl")),
        "xgb": xgb,
        "iso": joblib.load(os.path.join(MODELS_DIR, "isolation_forest.pkl")),

        # Encoders / transformers
        "le":     joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl")),
        "scaler": joblib.load(os.path.join(MODELS_DIR, "robust_scaler.pkl")),

        # Feature lists
        # selected_features → 40 columns RF + XGB expect (raw, unscaled)
        # top15_features    → 15 columns ISO expects (scaled)
        "selected_features": joblib.load(os.path.join(MODELS_DIR, "selected_features.pkl")),
        "top15_features":    joblib.load(os.path.join(MODELS_DIR, "top15_features.pkl")),
    }

    print(f"[load_models] Done.")
    print(f"  RF / XGB features : {len(models['selected_features'])} (raw)")
    print(f"  ISO features       : {len(models['top15_features'])} (scaled)")
    return models