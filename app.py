"""Flask dashboard for the local-only misconfiguration scanner."""

from concurrent.futures import ThreadPoolExecutor

from flask import Flask, abort, jsonify, render_template, request, send_file

from config import REPORTS_DIR, SECRET_KEY
from database import db
from main import compare_scans, execute_scan, generate_reports
from modules.safe_http import UnsafeTargetError, validate_local_url

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=16 * 1024)
executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scanner")
db.initialize_db()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.get("/history")
def history_page():
    return render_template("history.html")


@app.get("/scans/<int:scan_id>")
def results_page(scan_id):
    scan = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("results.html", scan=scan)


@app.get("/api/scans")
def scans_list():
    return jsonify(db.list_scans())


@app.post("/api/scans")
def create_scan():
    data = request.get_json(silent=True) or {}
    if data.get("authorized") is not True:
        return jsonify(error="Confirm that you own or are authorized to test this local target."), 400
    try:
        target_url = validate_local_url(data.get("target_url", ""))
    except UnsafeTargetError as exc:
        return jsonify(error=str(exc)), 400

    scan_id = db.create_scan(target_url)
    executor.submit(_run_scan, scan_id, target_url)
    return jsonify(id=scan_id, status="queued"), 202


@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    return jsonify(scan)


@app.get("/api/scans/<int:scan_id>/compare/<int:previous_id>")
def scan_comparison(scan_id, previous_id):
    current = db.get_scan(scan_id)
    previous = db.get_scan(previous_id)
    if current is None or previous is None:
        abort(404)
    if current["target_url"] != previous["target_url"]:
        return jsonify(error="Only scans of the same target can be compared."), 400
    return jsonify(compare_scans(current, previous))


@app.get("/api/scans/<int:scan_id>/reports/<report_format>")
def download_report(scan_id, report_format):
    if report_format not in {"json", "html", "pdf"}:
        abort(404)
    scan = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    path = (REPORTS_DIR / f"scan-{scan_id}.{report_format}").resolve()
    if path.parent != REPORTS_DIR.resolve():
        abort(404)
    if not path.exists():
        generate_reports(scan)
    return send_file(path, as_attachment=report_format != "html")


def _run_scan(scan_id, target_url):
    try:
        execute_scan(scan_id, target_url)
    except Exception as exc:
        db.update_scan(
            scan_id,
            status="failed",
            current_step="Scan failed",
            finished=True,
            error=f"Unexpected scanner failure: {type(exc).__name__}: {str(exc)[:300]}",
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
