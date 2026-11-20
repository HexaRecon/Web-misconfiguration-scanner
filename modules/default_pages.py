"""Detect a small set of common default or diagnostic pages."""

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from config import DEFAULT_PAGE_PATHS
from modules.risk_scoring import severity_for

SIGNATURES = {
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version\s*</td>", re.IGNORECASE),
    "/server-status": re.compile(r"Apache Server Status|Server uptime:", re.IGNORECASE),
    "/apache2-default/": re.compile(r"It works!|Apache2 Ubuntu Default Page", re.IGNORECASE),
    "/iisstart.htm": re.compile(r"IIS Windows Server|Internet Information Services", re.IGNORECASE),
    "/webadmin/install.php": re.compile(r"installation|setup wizard", re.IGNORECASE),
    "/wp-admin/install.php": re.compile(r"WordPress|installing WordPress", re.IGNORECASE),
}


def scan(base_url, client):
    findings = []
    for path in DEFAULT_PAGE_PATHS:
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = client.request("GET", target)
        try:
            if response.status_code != 200:
                continue
            page_text = BeautifulSoup(response.text[:8192], "html.parser").get_text(" ", strip=True)
            if not SIGNATURES[path].search(page_text):
                continue
            findings.append({
                "title": "Default or diagnostic page is accessible",
                "target_url": target,
                "detection_method": "GET request and page signature check",
                "http_status": response.status_code,
                "evidence": f"Recognized a known page signature at {path}; response content was not retained.",
                "severity": severity_for("default_diagnostic_page", diagnostic_signature=True),
                "description": "A recognizable default or diagnostic page is accessible and may expose implementation details.",
                "remediation": "Remove or restrict the page and disable diagnostics on publicly reachable deployments.",
            })
        finally:
            response.close()
    return findings
