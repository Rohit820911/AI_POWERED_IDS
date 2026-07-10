"""
app.py — Flask entry point. API only, no ML logic here.
"""

import os
import uuid
import json
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

from src.models.load_models import load_all_models
from src.models.preprocess import prepare_inputs
from src.models.predictor import predict_rf, predict_xgb, predict_iso, summarise
from src.models.live_capture import init_live_capture



BASE          = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE, "uploads")
RESULTS_DIR   = os.path.join(BASE, "results")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_DIR,   exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE, "templates"),
    static_folder=os.path.join(BASE, "static"),
)
app.config["UPLOAD_FOLDER"]      = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file attached"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only CSV files are accepted"}), 415

    filename  = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{filename}")
    file.save(save_path)

    row_count = col_count = 0
    with open(save_path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i == 0:
                col_count = len(line.split(","))
            elif line.strip():
                row_count += 1

    return jsonify({
        "success":  True,
        "filename": filename,
        "path":     save_path,
        "rows":     row_count,
        "columns":  col_count,
    })


@app.route("/api/analyse", methods=["POST"])
def analyse():
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "No file path provided"}), 400

    csv_path = data["path"]
    if not csv_path.startswith(UPLOAD_FOLDER):
        return jsonify({"error": "Invalid file path"}), 400
    if not os.path.exists(csv_path):
        return jsonify({"error": "File not found — did upload succeed?"}), 404

    try:
        df = pd.read_csv(csv_path, low_memory=False)

        X_raw, X_iso = prepare_inputs(df, models)

        rf_labels,  rf_probas  = predict_rf(X_raw, models)
        xgb_labels, xgb_probas = predict_xgb(X_raw, models)
        iso_scores             = predict_iso(X_iso, models)

        result = summarise(rf_labels, rf_probas, xgb_labels, xgb_probas, iso_scores)

        # Save summary (no sample_flows) to latest.json — lightweight for dashboard
        summary = {k: v for k, v in result.items() if k != "sample_flows"}
        latest_path = os.path.join(RESULTS_DIR, "latest.json")
        with open(latest_path, "w") as f:
            json.dump(summary, f, indent=2)

        # Save flows separately — served paginated via /api/flows
        flows_path = os.path.join(RESULTS_DIR, "flows.json")
        with open(flows_path, "w") as f:
            json.dump(result["sample_flows"], f)

        os.remove(csv_path)
        return jsonify({"success": True, **summary})

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

models = load_all_models()
init_live_capture(app, models)   # registers /api/live/start, /api/live/stop, /api/live

@app.route("/api/results")
def get_results():
    """Any dashboard page can call this to get the latest prediction results."""
    latest_path = os.path.join(RESULTS_DIR, "latest.json")
    if not os.path.exists(latest_path):
        return jsonify({"error": "No results yet — upload a CSV first"}), 404
    with open(latest_path) as f:
        return jsonify(json.load(f))


@app.route("/api/flows")
def get_flows():
    """
    Paginated flow endpoint. Query params:
      page     int  (1-based, default 1)
      per_page int  (default 200, max 2000)
      fmt      str  'json'|'csv' — 'csv' streams the full file for download
    """
    flows_path = os.path.join(RESULTS_DIR, "flows.json")
    if not os.path.exists(flows_path):
        return jsonify({"error": "No flows yet — upload a CSV first"}), 404

    fmt = request.args.get("fmt", "json")

    # Full CSV download — stream entire flows as CSV
    if fmt == "csv":
        import csv, io
        with open(flows_path) as f:
            flows = json.load(f)
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["row", "rf", "xgb", "iso", "confidence"])
        writer.writeheader()
        for fl in flows:
            writer.writerow(fl)
        from flask import Response
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=ai_ids_all_flows.csv"}
        )

    # Paginated JSON
    with open(flows_path) as f:
        flows = json.load(f)

    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(2000, max(1, int(request.args.get("per_page", 200))))
    total    = len(flows)
    start    = (page - 1) * per_page
    end      = start + per_page

    return jsonify({
        "page":        page,
        "per_page":    per_page,
        "total":       total,
        "total_pages": -(-total // per_page),
        "flows":       flows[start:end],
    })


@app.route('/reports/figures/<filename>')
def report_figure(filename):
    figures_dir = os.path.join(BASE, 'reports', 'figures')
    return send_from_directory(figures_dir, filename)


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File exceeds 200 MB limit"}), 413


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)