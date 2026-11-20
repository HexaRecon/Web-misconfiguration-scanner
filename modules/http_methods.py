"""Check which HTTP methods the local origin advertises."""

from urllib.parse import urljoin

RISKY_METHOD_GUIDANCE = {
    "TRACE": "Review whether TRACE is needed; it can echo request data in some configurations.",
    "PUT": "Review whether PUT is needed and ensure uploads are authenticated and constrained.",
    "DELETE": "Review whether DELETE is needed and ensure destructive actions require authorization.",
}


def scan(base_url, client):
    response = client.request("OPTIONS", base_url)
    try:
        allow = response.headers.get("Allow", "")
        methods = sorted({item.strip().upper() for item in allow.split(",") if item.strip()})
        if not methods:
            return []
        risky = [method for method in methods if method in RISKY_METHOD_GUIDANCE]
        evidence = "Advertised methods: " + ", ".join(methods[:20])
        if risky:
            evidence += ". Review: " + " ".join(
                f"{method}: {RISKY_METHOD_GUIDANCE[method]}" for method in risky
            )
        return [{
            "title": "HTTP methods advertised by the server",
            "target_url": urljoin(base_url, "/"),
            "detection_method": "HTTP OPTIONS",
            "http_status": response.status_code,
            "evidence": evidence[:500],
            "severity": "Informational",
            "description": (
                "The server advertised these methods in its Allow header. An enabled method "
                "is not by itself a vulnerability; verify that each is required and access-controlled."
            ),
            "remediation": "Disable unnecessary methods and verify authorization for methods that remain enabled.",
        }]
    finally:
        response.close()
