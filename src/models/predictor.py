"""
predictor.py
------------
Prediction functions. Flask calls these — no ML logic in app.py.
"""

import numpy as np

CHUNK = 5000


def _clean_label(label: str) -> str:
    """Fix mojibake from the CIC-IDS dataset (e.g. 'Web Attack \ufffd Brute Force')."""
    return label.replace("\ufffd", "-").replace("�", "-")


def predict_rf(X_raw: np.ndarray, models: dict) -> tuple:
    """Random Forest — raw unscaled 40-feature input.
    Returns (label_strings, max_proba_per_row).
    """
    rf, le = models["rf"], models["le"]
    preds, probas = [], []
    for i in range(0, len(X_raw), CHUNK):
        chunk = X_raw[i: i + CHUNK]
        preds.extend(rf.predict(chunk).tolist())
        p = rf.predict_proba(chunk)
        probas.extend(p.max(axis=1).tolist())
    labels = [_clean_label(l) for l in le.inverse_transform(preds).tolist()]
    return labels, probas


def predict_xgb(X_raw: np.ndarray, models: dict) -> tuple:
    """XGBoost — raw unscaled 40-feature input.
    Returns (label_strings, max_proba_per_row).
    """
    xgb, le = models["xgb"], models["le"]
    preds, probas = [], []
    for i in range(0, len(X_raw), CHUNK):
        chunk = X_raw[i: i + CHUNK]
        preds.extend(xgb.predict(chunk).tolist())
        p = xgb.predict_proba(chunk)
        probas.extend(p.max(axis=1).tolist())
    labels = [_clean_label(l) for l in le.inverse_transform(preds).tolist()]
    return labels, probas


def predict_iso(X_iso: np.ndarray, models: dict) -> list:
    """Isolation Forest — scaled top-15-feature input. Returns anomaly scores."""
    iso = models["iso"]
    scores = []
    for i in range(0, len(X_iso), CHUNK):
        scores.extend(iso.decision_function(X_iso[i: i + CHUNK]).tolist())
    return scores


def summarise(
    rf_labels: list, rf_probas: list,
    xgb_labels: list, xgb_probas: list,
    iso_scores: list,
) -> dict:
    """
    Combines all three model outputs.
    Adds per-flow confidence scores. Returns ALL flagged flows (no cap).
    """
    rf_arr   = np.array(rf_labels)
    xgb_arr  = np.array(xgb_labels)
    iso_arr  = np.array(iso_scores)
    rf_p_arr = np.array(rf_probas)
    xgb_p_arr= np.array(xgb_probas)

    total         = len(rf_arr)
    rf_threats    = int(np.sum(rf_arr  != "BENIGN"))
    xgb_threats   = int(np.sum(xgb_arr != "BENIGN"))
    iso_anomalies = int(np.sum(iso_arr < -0.5))
    ensemble      = int(np.sum(
        (rf_arr != "BENIGN") | (xgb_arr != "BENIGN") | (iso_arr < -0.5)
    ))

    # Full label distribution — BENIGN + every attack type
    unique, counts = np.unique(rf_arr, return_counts=True)
    label_distribution = dict(zip(unique.tolist(), counts.tolist()))

    # Attack-only breakdown (no BENIGN)
    attack_breakdown = {k: v for k, v in label_distribution.items() if k != "BENIGN"}

    # ALL flagged flows — no cap, so the frontend can download everything
    flagged_idx = [
        i for i in range(total)
        if rf_arr[i] != "BENIGN" or xgb_arr[i] != "BENIGN" or iso_arr[i] < -0.5
    ]

    sample_flows = []
    for i in flagged_idx:
        # Ensemble confidence: average of RF and XGB max probabilities
        conf = round(float((rf_p_arr[i] + xgb_p_arr[i]) / 2) * 100, 2)
        sample_flows.append({
            "row":        int(i),
            "rf":         rf_arr[i],
            "xgb":        xgb_arr[i],
            "iso":        round(float(iso_arr[i]), 3),
            "confidence": conf,
        })

    return {
        "total_flows":        total,
        "rf_threats":         rf_threats,
        "xgb_threats":        xgb_threats,
        "iso_anomalies":      iso_anomalies,
        "ensemble_threats":   ensemble,
        "benign_count":       int(label_distribution.get("BENIGN", 0)),
        "detection_rate":     round(ensemble / max(total, 1) * 100, 2),
        "label_distribution": label_distribution,
        "attack_breakdown":   attack_breakdown,
        "sample_flows":       sample_flows,
    }