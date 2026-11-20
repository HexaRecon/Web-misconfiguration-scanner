"""Check fixed sensitive-file paths without retaining response contents."""

import re
from urllib.parse import urljoin

from modules.risk_scoring import severity_for

from config import EXPOSED_FILE_PATHS

FILE_SIGNATURES = {
    "/.env": re.compile(rb"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*="),
    "/.git/config": re.compile(rb"(?is)\[core\]\s*.*?repositoryformatversion"),
    "/config.php.bak": re.compile(rb"(?is)<\?php|(?:database|db_name|db_user)\s*['\"]?\s*=>"),
    "/web.config": re.compile(rb"(?is)<configuration(?:\s|>)"),
    "/wp-config.php~": re.compile(rb"(?is)<\?php|DB_(?:NAME|USER|PASSWORD)"),
    "/backup.zip": re.compile(rb"^PK\x03\x04"),
}


def scan(base_url, client):
    findings = []
    for path in EXPOSED_FILE_PATHS:
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = client.request(
            "GET",
            target,
            max_response_bytes=2048,
            headers={"Range": "bytes=0-2047"},
        )
        try:
            if response.status_code not in {200, 206}:
                continue
            prefix = response.content[:2048]
            if not FILE_SIGNATURES[path].search(prefix):
                continue
            findings.append({
                "title": "Potentially sensitive configuration or backup file exposed",
                "target_url": target,
                "detection_method": "GET request and file-format signature check",
                "http_status": response.status_code,
                "evidence": (
                    f"Recognized the expected file signature for {path}; "
                    "file contents and secrets were not retained."
                ),
                "severity": severity_for("exposed_configuration", content_signature=True),
                "description": "A known configuration or backup file is reachable and its format was verified.",
                "remediation": "Remove the file from the web root, rotate any credentials that may have been exposed, and review access logs.",
            })
        finally:
            response.close()
    return findings
