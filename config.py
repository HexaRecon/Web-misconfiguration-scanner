"""Application settings and safety limits."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database" / "scanner.sqlite3"
REPORTS_DIR = BASE_DIR / "reports"
NUCLEI_TEMPLATE = BASE_DIR / "nuclei-templates" / "safe-headers.yaml"

HTTP_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 512 * 1024
REQUEST_INTERVAL_SECONDS = 0.5
NUCLEI_TIMEOUT_SECONDS = 45
SCAN_PATHS = (
    "/uploads/",
    "/backup/",
    "/images/",
    "/files/",
    "/documents/",
)
DEFAULT_PAGE_PATHS = (
    "/phpinfo.php",
    "/server-status",
    "/apache2-default/",
    "/iisstart.htm",
    "/webadmin/install.php",
    "/wp-admin/install.php",
)
EXPOSED_FILE_PATHS = (
    "/.env",
    "/.git/config",
    "/config.php.bak",
    "/web.config",
    "/wp-config.php~",
    "/backup.zip",
)

SECRET_KEY = os.environ.get("SCANNER_SECRET_KEY", "local-development-only-change-me")
