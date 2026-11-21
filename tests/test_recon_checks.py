"""Unit tests for KI-3 recon checks against MockBank."""

import threading
import time
import unittest
from http.server import HTTPServer

from mockbank.server import DEFAULT_HOST, MockBankHandler
from recon.base import validate_result
from recon.checks import (
    RECON_CHECKS,
    check_caching_csrf,
    check_metadata_disclosure,
    check_security_headers,
)

TEST_PORT = 8993
BASE_URL = f"http://{DEFAULT_HOST}:{TEST_PORT}"


class TestReconChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer((DEFAULT_HOST, TEST_PORT), MockBankHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_catalog_has_ki3_checks(self):
        self.assertEqual(
            set(RECON_CHECKS),
            {"security_headers", "metadata_disclosure", "caching_and_csrf"},
        )

    def test_refuses_non_localhost(self):
        for fn in (
            check_security_headers,
            check_metadata_disclosure,
            check_caching_csrf,
        ):
            res = fn("http://example.com")
            validate_result(res)
            self.assertEqual(res["status"], "error")
            self.assertEqual(res["severity"], "high")

    def test_security_headers_fail_on_mockbank(self):
        res = check_security_headers(BASE_URL)
        validate_result(res)
        self.assertEqual(res["check_name"], "security_headers")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["severity"], "medium")
        missing = res["raw_output"]["missing_headers"]
        self.assertIn("Content-Security-Policy", missing)
        self.assertIn("Strict-Transport-Security (HSTS)", missing)
        self.assertIn("X-Content-Type-Options", missing)

    def test_metadata_disclosure_fail_on_mockbank(self):
        res = check_metadata_disclosure(BASE_URL)
        validate_result(res)
        self.assertEqual(res["check_name"], "metadata_disclosure")
        self.assertEqual(res["status"], "fail")
        self.assertIn("Apache/2.4.41", res["raw_output"].get("server", ""))
        self.assertIn("PHP/8.0.12", res["raw_output"].get("x_powered_by", ""))
        self.assertIn("/admin/", res["raw_output"].get("disallowed_paths", []))
        self.assertEqual(res["raw_output"].get("discovered_ai_endpoint"), "/api/chat")

    def test_caching_csrf_warn_on_mockbank(self):
        res = check_caching_csrf(BASE_URL)
        validate_result(res)
        self.assertEqual(res["check_name"], "caching_and_csrf")
        self.assertEqual(res["status"], "warn")
        self.assertEqual(res["severity"], "medium")
        self.assertGreaterEqual(len(res["raw_output"].get("issues", [])), 2)


if __name__ == "__main__":
    unittest.main()
