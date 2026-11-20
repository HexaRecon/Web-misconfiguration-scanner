import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from database import db
from modules.directory_listing import scan as scan_directory_listing
from modules.safe_http import SafeHttpClient, UnsafeTargetError, validate_local_url
from main import execute_scan
from modules import nuclei_scan
from tests.local_test_app import demo
from werkzeug.serving import make_server


class TargetValidationTests(unittest.TestCase):
    def test_loopback_targets_are_normalized_to_origin(self):
        self.assertEqual(validate_local_url("http://127.0.0.1:8080/a?token=hidden"), "http://127.0.0.1:8080/")
        self.assertEqual(validate_local_url("http://localhost:5000/path"), "http://localhost:5000/")
        self.assertEqual(
            validate_local_url("http://127.0.0.1:8080/uploads/", preserve_path=True),
            "http://127.0.0.1:8080/uploads/",
        )

    def test_external_and_non_http_targets_are_rejected(self):
        for target in (
            "https://example.com",
            "http://192.168.1.1",
            "http://169.254.169.254/latest/meta-data",
            "file:///etc/passwd",
            "http://user:pass@localhost/",
        ):
            with self.subTest(target=target), self.assertRaises(UnsafeTargetError):
                validate_local_url(target)


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.executor_patch = patch("app.executor")
        self.executor_patch.start()
        self.addCleanup(self.executor_patch.stop)

    def test_dashboard_pages_render(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/history").status_code, 200)

    def test_scan_requires_authorization_and_rejects_external_target(self):
        response = self.client.post(
            "/api/scans",
            data=json.dumps({"target_url": "http://localhost:8000", "authorized": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/api/scans",
            data=json.dumps({"target_url": "http://example.com", "authorized": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_report_format_is_not_served(self):
        self.assertEqual(self.client.get("/api/scans/1/reports/txt").status_code, 404)

    def test_scans_of_different_targets_cannot_be_compared(self):
        scans = {
            1: {"id": 1, "target_url": "http://127.0.0.1:8000/", "findings": []},
            2: {"id": 2, "target_url": "http://127.0.0.1:9000/", "findings": []},
        }
        with patch("app.db.get_scan", side_effect=lambda scan_id: scans.get(scan_id)):
            response = self.client.get("/api/scans/1/compare/2")
        self.assertEqual(response.status_code, 400)


class DirectoryListingTests(unittest.TestCase):
    def test_recognized_index_page_reports_only_limited_safe_evidence(self):
        class FakeResponse:
            status_code = 200
            text = (
                "<html><title>Index of /uploads/</title><body>"
                "<a href='secret-backup.zip'>secret-backup.zip</a>"
                "<a href='second.txt'>second.txt</a></body></html>"
            )

            def close(self):
                pass

        class FakeClient:
            def request(self, method, url):
                if url.endswith("/uploads/"):
                    return FakeResponse()
                return type("Response", (), {"status_code": 404, "close": lambda self: None})()

        findings = scan_directory_listing("http://127.0.0.1:8000/", FakeClient())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")
        self.assertIn("secret-backup.zip", findings[0]["evidence"])


class SafeHttpClientTests(unittest.TestCase):
    def test_redirect_to_another_local_path_is_rejected(self):
        class FakeResponse:
            status_code = 302
            headers = {"Location": "/unexpected"}

            def close(self):
                pass

        with patch("modules.safe_http.requests.request", return_value=FakeResponse()):
            with self.assertRaises(UnsafeTargetError):
                SafeHttpClient().request("GET", "http://127.0.0.1:8000/uploads/")


class NucleiIntegrationTests(unittest.TestCase):
    def test_user_local_nuclei_install_is_discovered(self):
        with patch.dict("os.environ", {"LOCALAPPDATA": r"C:\Users\Tester\AppData\Local"}), \
                patch("modules.nuclei_scan.Path.is_file", return_value=True), \
                patch("modules.nuclei_scan.shutil.which", return_value=None):
            executable = nuclei_scan._user_installed_nuclei()
        self.assertEqual(
            executable,
            r"C:\Users\Tester\AppData\Local\Programs\Nuclei\nuclei.exe",
        )


class LocalScanIntegrationTests(unittest.TestCase):
    def test_local_demo_scan_persists_findings_and_creates_redacted_reports(self):
        server = make_server("127.0.0.1", 0, demo)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        target = f"http://127.0.0.1:{server.server_port}/"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("database.db.DATABASE_PATH", root / "scanner.sqlite3"), \
                    patch("main.REPORTS_DIR", root / "reports"), \
                    patch(
                        "main.nuclei_scan.scan",
                        return_value=([], "Nuclei not installed; bundled Nuclei header check was skipped."),
                    ):
                db.initialize_db()
                scan_id = db.create_scan(target)
                result = execute_scan(scan_id, target)
                titles = {finding["title"] for finding in result["findings"]}
                self.assertIn("Directory listing appears enabled", titles)
                self.assertIn("Default or diagnostic page is accessible", titles)
                self.assertIn("Potentially sensitive configuration or backup file exposed", titles)
                for extension in ("json", "html", "pdf"):
                    report = root / "reports" / f"scan-{scan_id}.{extension}"
                    self.assertTrue(report.is_file())
                    self.assertNotIn(b"DEMO_ONLY=dummy", report.read_bytes())
                self.assertEqual(result["status"], "completed_with_errors")


if __name__ == "__main__":
    unittest.main()
