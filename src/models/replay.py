"""
replay.py
---------
Live Replay Engine — feeds a pre-analysed sample_flows.csv through the
ML pipeline row-by-row on a timer, simulating real-time network traffic.

Architecture (from spec):
  sample_flows.csv → Replay Engine (current_pos) → batch read
  → Preprocess → RF / XGB / ISO → Update Live State → /api/live

Flask integration
-----------------
Call `init_replay(app, models)` once in app.py, right after `load_all_models()`.
That registers four routes on the app object:

  POST /api/replay/start   body: {"path": "<abs path to CSV>", "batch_size": 10, "interval": 1.0}
  POST /api/replay/stop
  GET  /api/replay/status
  GET  /api/live           — polled by dashboard every 2 s

The live state dict is kept in module-level memory; it resets on each /start.
"""

import csv
import io
import json
import threading
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from flask import jsonify, request

# ── Module-level state ────────────────────────────────────────────────────────

_lock       = threading.Lock()
_timer_ref  = [None]          # holds the current threading.Timer

_replay_state = {
    "running":        False,
    "csv_path":       None,
    "current_pos":    0,
    "batch_size":     10,
    "interval":       1.0,
    "rows_processed": 0,
    "started_at":     None,
    "error":          None,
}

# Live state — reset each /start; mutated each tick
_live = {
    "total_flows":       0,
    "benign_count":      0,
    "threat_count":      0,
    "rf_threats":        0,
    "xgb_threats":       0,
    "iso_anomalies":     0,
    "label_counts":      {},   # {"DDoS": 42, "PortScan": 7, ...}
    "latest_alerts":     [],   # last 50 attack events  [{ts, label, row, iso}]
    "timeline":          [],   # [{t, threats}]  last 120 points (~2 min at 1 s)
    "detection_rate":    0.0,
}

# Pre-loaded CSV rows cached as a list of dicts (header-stripped)
_csv_rows   = []
_csv_header = []

MAX_ALERTS   = 50
MAX_TIMELINE = 120


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso_bad(score: float) -> bool:
    return score < -0.5


def _reset_live():
    global _live
    _live = {
        "total_flows":    0,
        "benign_count":   0,
        "threat_count":   0,
        "rf_threats":     0,
        "xgb_threats":    0,
        "iso_anomalies":  0,
        "label_counts":   {},
        "latest_alerts":  [],
        "timeline":       [],
        "detection_rate": 0.0,
    }


def _load_csv(path: str):
    """Read the CSV once into memory as a list of row-dicts."""
    global _csv_rows, _csv_header
    with open(path, newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        _csv_header = list(reader.fieldnames or [])
        _csv_rows   = list(reader)


def _tick(models: dict, app):
    """Called once per interval by a background Timer."""
    # Reschedule first so drift doesn't accumulate
    with _lock:
        if not _replay_state["running"]:
            return
        interval = _replay_state["interval"]

    t = threading.Timer(interval, _tick, args=(models, app))
    t.daemon = True
    t.start()
    with _lock:
        _timer_ref[0] = t

    # Pull next batch from in-memory rows
    with _lock:
        pos        = _replay_state["current_pos"]
        batch_size = _replay_state["batch_size"]
        total_rows = len(_csv_rows)

    if pos >= total_rows:
        # Loop back to start
        with _lock:
            _replay_state["current_pos"] = 0
        return

    batch_dicts = _csv_rows[pos: pos + batch_size]
    with _lock:
        _replay_state["current_pos"]    = pos + len(batch_dicts)
        _replay_state["rows_processed"] += len(batch_dicts)

    if not batch_dicts:
        return

    # ── Run through app context so imports work ──────────────────────────────
    try:
        with app.app_context():
            from src.models.preprocess import prepare_inputs
            from src.models.predictor  import predict_rf, predict_xgb, predict_iso

            df = pd.DataFrame(batch_dicts)
            # Strip whitespace from column names (CIC-IDS quirk)
            df.columns = df.columns.str.strip()

            X_raw, X_iso = prepare_inputs(df, models)

            rf_labels,  rf_probas  = predict_rf(X_raw,  models)
            xgb_labels, xgb_probas = predict_xgb(X_raw, models)
            iso_scores             = predict_iso(X_iso,  models)
    except Exception as exc:
        with _lock:
            _replay_state["error"] = str(exc)
        return

    # ── Update live state ────────────────────────────────────────────────────
    ts_now = datetime.now(timezone.utc).isoformat()
    new_threats = 0

    with _lock:
        for i in range(len(rf_labels)):
            rf  = rf_labels[i]
            xgb = xgb_labels[i]
            iso = iso_scores[i]

            _live["total_flows"] += 1

            is_threat = (rf != "BENIGN") or (xgb != "BENIGN") or _iso_bad(iso)

            if is_threat:
                _live["threat_count"] += 1
                new_threats += 1
                label = rf if rf != "BENIGN" else (xgb if xgb != "BENIGN" else "Anomaly")
                _live["label_counts"][label] = _live["label_counts"].get(label, 0) + 1

                alert = {
                    "ts":    ts_now,
                    "label": label,
                    "row":   pos + i,
                    "iso":   round(iso, 3),
                }
                _live["latest_alerts"].insert(0, alert)
                if len(_live["latest_alerts"]) > MAX_ALERTS:
                    _live["latest_alerts"].pop()
            else:
                _live["benign_count"] += 1

            if rf != "BENIGN":
                _live["rf_threats"] += 1
            if xgb != "BENIGN":
                _live["xgb_threats"] += 1
            if _iso_bad(iso):
                _live["iso_anomalies"] += 1

        # Timeline point
        _live["timeline"].append({
            "t":       ts_now,
            "threats": _live["threat_count"],
            "new":     new_threats,
        })
        if len(_live["timeline"]) > MAX_TIMELINE:
            _live["timeline"].pop(0)

        total = max(_live["total_flows"], 1)
        _live["detection_rate"] = round(_live["threat_count"] / total * 100, 2)


# ── Route registration ────────────────────────────────────────────────────────

def init_replay(app, models: dict):
    """Register all /api/replay/* and /api/live routes on the Flask app."""

    @app.route("/api/replay/start", methods=["POST"])
    def replay_start():
        data = request.get_json() or {}
        path = data.get("path", "")
        if not path:
            return jsonify({"error": "path is required"}), 400
        import os
        if not os.path.isfile(path):
            return jsonify({"error": f"File not found: {path}"}), 404

        batch_size = int(data.get("batch_size", 10))
        interval   = float(data.get("interval", 1.0))

        with _lock:
            # Stop any running replay
            if _replay_state["running"] and _timer_ref[0]:
                _timer_ref[0].cancel()

        # Load CSV into memory
        try:
            _load_csv(path)
        except Exception as e:
            return jsonify({"error": f"Failed to read CSV: {e}"}), 500

        _reset_live()

        with _lock:
            _replay_state.update({
                "running":        True,
                "csv_path":       path,
                "current_pos":    0,
                "batch_size":     batch_size,
                "interval":       interval,
                "rows_processed": 0,
                "started_at":     datetime.now(timezone.utc).isoformat(),
                "error":          None,
            })

        # Kick off first tick
        t = threading.Timer(interval, _tick, args=(models, app))
        t.daemon = True
        t.start()
        with _lock:
            _timer_ref[0] = t

        return jsonify({
            "success":    True,
            "total_rows": len(_csv_rows),
            "batch_size": batch_size,
            "interval":   interval,
        })

    @app.route("/api/replay/stop", methods=["POST"])
    def replay_stop():
        with _lock:
            _replay_state["running"] = False
            if _timer_ref[0]:
                _timer_ref[0].cancel()
                _timer_ref[0] = None
        return jsonify({"success": True})

    @app.route("/api/replay/status")
    def replay_status():
        with _lock:
            state = dict(_replay_state)
            state["total_rows"] = len(_csv_rows)
        return jsonify(state)

    @app.route("/api/live")
    def live_state():
        with _lock:
            snap = {
                "running":        _replay_state["running"],
                "rows_processed": _replay_state["rows_processed"],
                "total_rows":     len(_csv_rows),
                **_live,
            }
        return jsonify(snap)