"""Look for recognizable directory-index pages at a fixed set of paths."""

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from config import SCAN_PATHS
from modules.risk_scoring import severity_for

INDEX_MARKERS = (
    re.compile(r"\bIndex of\s+/", re.IGNORECASE),
    re.compile(r"\bDirectory listing for\s+/", re.IGNORECASE),
)
def scan(base_url, client):
    findings = []
    for path in SCAN_PATHS:
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = client.request("GET", target)
        try:
            if response.status_code != 200:
                continue
            soup = BeautifulSoup(response.text[:8192], "html.parser")
            page_text = soup.get_text(" ", strip=True)
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            headings = " ".join(tag.get_text(" ", strip=True) for tag in soup.find_all(["h1", "h2"]))
            title_and_headings = f"{title} {headings}"
            if not any(marker.search(title_and_headings) for marker in INDEX_MARKERS):
                continue
            names = []
            for link in soup.find_all("a", href=True):
                href = str(link["href"])
                name = href.split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
                if name and name not in {".", ".."} and not href.lower().startswith(("http:", "https:")):
                    names.append(name[:80])
                if len(names) >= 5:
                    break
            evidence = "Recognized directory-index page."
            if names:
                evidence += " Sample names: " + ", ".join(names)
            findings.append({
                "title": "Directory listing appears enabled",
                "target_url": target,
                "detection_method": "GET request and directory-index signature check",
                "http_status": response.status_code,
                "evidence": evidence[:500],
                "severity": severity_for("directory_listing", listing_signature=True),
                "description": "A directory index page is publicly accessible and may disclose file names.",
                "remediation": "Disable directory indexing and restrict access to files that are not intended to be public.",
            })
        finally:
            response.close()
    return findings
