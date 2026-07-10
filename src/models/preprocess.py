"""
preprocess.py
-------------
Aligns an uploaded CSV to exactly what each model expects.

Training pipeline (from notebook):
  Raw CSV (79 cols)
      ↓ drop zero-variance + high-correlation cols
      ↓ 40 features remain  →  RF gets these RAW
                            →  XGB gets these RAW
      ↓ pick top 15 by RF importance
      ↓ RobustScaler (fitted on BENIGN only)
                            →  ISO gets these SCALED

So this module returns TWO arrays:
  X_raw   shape (n, 40)  — for RF and XGB
  X_iso   shape (n, 15)  — for Isolation Forest
"""

import numpy as np
import pandas as pd


def align_columns(df: pd.DataFrame, selected_features: list) -> pd.DataFrame:
    """
    Takes a raw uploaded DataFrame and aligns it to the 40 training features.
      - Strips column name whitespace
      - Drops Label column if present
      - Fills any missing features with 0
      - Drops extra columns
      - Reorders to exact training order
      - Replaces inf / NaN with 0
    """
    df = df.copy()
    df.columns = df.columns.str.strip()

    # Drop label column if present (CIC-IDS datasets include it)
    for label_col in ["Label", " Label", "label"]:
        if label_col in df.columns:
            df = df.drop(columns=[label_col])

    # Fill missing features with 0 and warn
    missing = [f for f in selected_features if f not in df.columns]
    if missing:
        print(f"[preprocess] Warning — {len(missing)} missing columns filled with 0: {missing[:5]}")
        for col in missing:
            df[col] = 0.0

    # Select + reorder to exact training order (drops unknown extra columns)
    df = df[list(selected_features)]

    # Replace inf / NaN with 0
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    return df


def prepare_inputs(df: pd.DataFrame, models: dict) -> tuple:
    """
    Full preprocessing pipeline. Returns:
      X_raw  np.ndarray  shape (n, 40)  → pass to RF and XGB
      X_iso  np.ndarray  shape (n, 15)  → pass to Isolation Forest

    Args:
      df     : raw uploaded DataFrame (any column order, may have extra/missing cols)
      models : dict returned by load_all_models()
    """
    selected_features = models["selected_features"]
    top15_features    = models["top15_features"]
    scaler            = models["scaler"]

    # Step 1 — align to 40 training columns
    aligned = align_columns(df, selected_features)
    X_raw   = aligned.values.astype(float)          # RF + XGB use this (raw, unscaled)

    # Step 2 — slice to top-15, then scale for ISO
    top15_idx = [list(selected_features).index(f) for f in top15_features]
    X_top15   = X_raw[:, top15_idx]                 # shape (n, 15), still unscaled
    X_iso     = scaler.transform(X_top15)            # shape (n, 15), scaled

    return X_raw, X_iso