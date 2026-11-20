"""Scan orchestration and report generation."""

import html
import json
from datetime import datetime, timezone

from config import REPORTS_DIR
from database import db
from modules import default_pages, directory_listing, exposed_files, http_methods, nuclei_scan
from modules.safe_http import SafeHttpClient, validate_local_url

CHECKS = (
    ("HTTP methods", lambda url, client: http_methods.scan(url, client)),
    ("Directory listings", lambda url, client: directory_listing.scan(url, client)),
    ("Default pages", lambda url, client: default_pages.scan(url, client)),
    ("Exposed files", lambda url, client: exposed_files.scan(url, client)),
)


def execute_scan(scan_id, target_url):
    """Run fixed checks, saving findings and visible progress after each stage."""
    target_url = validate_local_url(target_url)
    db.update_scan(scan_id, status="running", progress=0, current_step="Starting checks")
    client = SafeHttpClient()
    errors = []
    completed = 0
    total = len(CHECKS) + 1
    for name, check in CHECKS:
        try:
            findings = check(target_url, client)
            db.add_findings(scan_id, findings)
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:300]}")
        completed += 1
        db.update_scan(
            scan_id,
            progress=int(completed * 100 / total),
            current_step=f"Completed {name}",
        )

    try:
        findings, nuclei_error = nuclei_scan.scan(target_url)
        db.add_findings(scan_id, findings)
        if nuclei_error:
            errors.append(nuclei_error)
    except (OSError, ValueError, RuntimeError) as exc:
        errors.append(f"Nuclei check: {type(exc).__name__}: {str(exc)[:300]}")
    completed += 1

    status = "completed_with_errors" if errors else "completed"
    db.update_scan(
        scan_id,
        status=status,
        progress=100,
        current_step="Scan finished",
        finished=True,
        error="\n".join(errors) if errors else None,
    )
    scan = db.get_scan(scan_id)
    generate_reports(scan)
    return scan


def generate_reports(scan):
    """Write JSON, escaped HTML, and PDF reports for a completed scan."""
    if scan is None:
        raise ValueError("Cannot create a report for an unknown scan.")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = int(scan["id"])
    payload = _report_payload(scan)
    stem = REPORTS_DIR / f"scan-{scan_id}"
    (stem.with_suffix(".json")).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (stem.with_suffix(".html")).write_text(_html_report(payload), encoding="utf-8")
    _write_pdf(stem.with_suffix(".pdf"), payload)


def _report_payload(scan):
    findings = scan.get("findings", [])
    counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("Critical", "High", "Medium", "Low", "Informational")
    }
    return {
        "report_title": "Website Misconfiguration Scanner Report",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan": {key: scan.get(key) for key in (
            "id", "target_url", "status", "started_at", "finished_at", "error"
        )},
        "executive_summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "summary": (
                f"The scan recorded {len(findings)} finding(s). "
                "Review each observation and validate it in the target environment."
            ),
        },
        "findings": [
            {key: item.get(key) for key in (
                "title", "target_url", "detection_method", "http_status",
                "evidence", "severity", "description", "remediation"
            )}
            for item in findings
        ],
    }


def _html_report(payload):
    esc = html.escape
    counts = payload["executive_summary"]["severity_counts"]
    summary = "".join(
        f"<li>{esc(severity)}: {count}</li>" for severity, count in counts.items()
    )
    findings_html = []
    for item in payload["findings"]:
        status = item.get("http_status")
        findings_html.append(
            "<article class='finding'>"
            f"<h2>{esc(str(item['title']))} <span>{esc(str(item['severity']))}</span></h2>"
            f"<p><b>Target:</b> {esc(str(item['target_url']))}</p>"
            f"<p><b>Detection:</b> {esc(str(item['detection_method']))}</p>"
            f"<p><b>HTTP status:</b> {esc(str(status if status is not None else 'Not reported'))}</p>"
            f"<p><b>Evidence:</b> {esc(str(item['evidence']))}</p>"
            f"<p>{esc(str(item['description']))}</p>"
            f"<p><b>Remediation:</b> {esc(str(item['remediation']))}</p></article>"
        )
    if not findings_html:
        findings_html.append("<p>No findings were recorded.</p>")
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Scanner Report</title><style>"
        "body{font:16px system-ui;background:#0b1220;color:#e5eaf3;max-width:980px;"
        "margin:40px auto;padding:0 20px}article{background:#121d30;padding:20px;"
        "margin:16px 0;border-radius:12px;border:1px solid #25334b}span{color:#fbbf24}"
        "a{color:#7dd3fc}</style><body>"
        f"<h1>{esc(payload['report_title'])}</h1>"
        f"<p>Scan #{payload['scan']['id']} — {esc(str(payload['scan']['target_url']))}</p>"
        f"<h2>Executive summary</h2><p>{esc(payload['executive_summary']['summary'])}</p>"
        f"<ul>{summary}</ul><h2>Findings</h2>{''.join(findings_html)}</body></html>"
    )


def _write_pdf(path, payload):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading2"], textColor=colors.HexColor("#143453")))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"], alignment=TA_LEFT, leading=14))
    story = [
        Paragraph(html.escape(payload["report_title"]), styles["Title"]),
        Spacer(1, 0.15 * inch),
        Paragraph(f"Scan #{payload['scan']['id']} — {html.escape(str(payload['scan']['target_url']))}", styles["BodyText"]),
        Paragraph("Executive summary", styles["Heading1"]),
        Paragraph(html.escape(payload["executive_summary"]["summary"]), styles["SmallBody"]),
        Paragraph(
            "Severity counts: " + ", ".join(
                f"{html.escape(key)} {value}"
                for key, value in payload["executive_summary"]["severity_counts"].items()
            ),
            styles["SmallBody"],
        ),
        Paragraph("Findings", styles["Heading1"]),
    ]
    if not payload["findings"]:
        story.append(Paragraph("No findings were recorded.", styles["SmallBody"]))
    for item in payload["findings"]:
        status = item.get("http_status")
        pieces = (
            ("Target", item["target_url"]),
            ("Detection", item["detection_method"]),
            ("HTTP status", status if status is not None else "Not reported"),
            ("Severity", item["severity"]),
            ("Evidence", item["evidence"]),
            ("Description", item["description"]),
            ("Remediation", item["remediation"]),
        )
        story.append(Paragraph(html.escape(str(item["title"])), styles["FindingTitle"]))
        for label, value in pieces:
            story.append(Paragraph(f"<b>{label}:</b> {html.escape(str(value))}", styles["SmallBody"]))
        story.append(Spacer(1, 0.12 * inch))
    SimpleDocTemplate(str(path), pagesize=letter, title="Scanner Report").build(story)


def compare_scans(current, previous):
    """Compare findings by stable title, target, and detection-method identity."""
    def keyed(findings):
        return {
            (item["title"], item["target_url"], item["detection_method"]): item
            for item in findings
        }

    current_items = keyed(current.get("findings", []))
    previous_items = keyed(previous.get("findings", []))
    return {
        "new": [current_items[key] for key in current_items.keys() - previous_items.keys()],
        "resolved": [previous_items[key] for key in previous_items.keys() - current_items.keys()],
        "persistent": [current_items[key] for key in current_items.keys() & previous_items.keys()],
    }
