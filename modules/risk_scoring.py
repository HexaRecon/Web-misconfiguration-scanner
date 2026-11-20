"""Consistent severity mapping for verified, non-exploitative observations."""

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def severity_for(kind, **evidence):
    """Return severity only when the check has evidence beyond an HTTP status."""
    if kind == "directory_listing" and evidence.get("listing_signature"):
        return "Medium"
    if kind == "default_diagnostic_page" and evidence.get("diagnostic_signature"):
        return "Medium"
    if kind == "exposed_configuration" and evidence.get("content_signature"):
        return "High"
    if kind == "nuclei_header":
        return evidence.get("nuclei_severity", "Informational").capitalize()
    return "Informational"
