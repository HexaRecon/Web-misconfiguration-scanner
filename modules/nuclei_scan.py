"""Run one bundled, non-intrusive Nuclei HTTP-header template."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from config import NUCLEI_TEMPLATE, NUCLEI_TIMEOUT_SECONDS
from modules.safe_http import validate_local_url

SEVERITIES = {"info": "Informational", "low": "Low", "medium": "Medium"}


def scan(base_url):
    base_url = validate_local_url(base_url)
    executable = shutil.which("nuclei") or _user_installed_nuclei()
    if not executable:
        return [], "Nuclei is not installed; bundled Nuclei header check was skipped."

    command = [
        executable,
        "-u", base_url,
        "-t", str(NUCLEI_TEMPLATE),
        "-severity", "info,low,medium",
        "-rl", "1",
        "-c", "1",
        "-timeout", "5",
        "-retries", "0",
        "-rsr", "2048",
        "-rss", "1024",
        "-disable-update-check",
        "-no-interactsh",
        "-omit-raw",
        "-jsonl",
        "-silent",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return [], f"Nuclei check exceeded the {NUCLEI_TIMEOUT_SECONDS}-second timeout."
    except OSError as exc:
        return [], f"Could not start Nuclei: {type(exc).__name__}."

    findings = []
    for line in result.stdout.splitlines()[:100]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        raw_severity = str(info.get("severity", "info")).lower()
        if raw_severity not in SEVERITIES:
            continue
        template_id = str(item.get("template-id", "header-check"))[:100]
        name = str(info.get("name", "Nuclei safe header check"))[:150]
        matched_at = str(item.get("matched-at", base_url))[:300]
        findings.append({
            "title": name,
            "target_url": matched_at,
            "detection_method": f"Nuclei bundled safe template ({template_id})",
            "http_status": None,
            "evidence": f"Template {template_id} matched; no response body or secret values are included.",
            "severity": SEVERITIES[raw_severity],
            "description": str(info.get("description", "A configured HTTP security-header check matched."))[:1000],
            "remediation": str(
                info.get("remediation")
                or "Review the relevant HTTP security header and configure it where appropriate."
            )[:1000],
        })
    error = None
    if result.returncode not in (0, 1):
        error = f"Nuclei exited with status {result.returncode}."
    return findings, error


def _user_installed_nuclei():
    """Find a user-local Windows installation without requiring a process restart."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    executable = Path(local_app_data) / "Programs" / "Nuclei" / "nuclei.exe"
    return str(executable) if executable.is_file() else None
