"""Tests for the shared contract helpers in recon/base.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon.base import is_local_target, make_result, validate_result  # noqa: E402


def example():
    return {
        "check_name": "security_headers",
        "target": "http://127.0.0.1:8000",
        "status": "warn",
        "severity": "low",
        "evidence": "Response is missing Content-Security-Policy.",
        "raw_output": {"header_present": False},
        "timestamp": "2026-11-11T18:00:00Z",
    }


class TestMakeResult(unittest.TestCase):
    def test_builds_valid_result(self):
        r = make_result("security_headers", "http://127.0.0.1:8000", "warn", "low",
                        "Response is missing Content-Security-Policy.",
                        {"header_present": False})
        validate_result(r)
        self.assertEqual(r["status"], "warn")

    def test_timestamp_ends_in_z(self):
        r = make_result("x", "http://localhost", "pass", "info", "ok")
        self.assertTrue(r["timestamp"].endswith("Z"))
        self.assertEqual(r["raw_output"], {})

    def test_rejects_bad_status(self):
        with self.assertRaises(ValueError):
            make_result("x", "http://localhost", "ok", "info", "ok")


class TestValidateResult(unittest.TestCase):
    def test_example_is_valid(self):
        validate_result(example())

    def test_missing_field(self):
        r = example()
        del r["evidence"]
        with self.assertRaisesRegex(ValueError, "evidence"):
            validate_result(r)

    def test_bad_severity(self):
        r = example()
        r["severity"] = "critical"
        with self.assertRaisesRegex(ValueError, "severity"):
            validate_result(r)

    def test_simulated_and_not_tested_allowed(self):
        for status in ("simulated", "not_tested"):
            r = example()
            r["status"] = status
            validate_result(r)

    def test_rejects_non_z_timestamps(self):
        for ts in ("2026-11-11T18:00:00+00:00", "2026-11-11T18:00:00", "yesterday", "2026-13-40T99:00:00Z"):
            r = example()
            r["timestamp"] = ts
            with self.assertRaises(ValueError, msg=ts):
                validate_result(r)


class TestIsLocalTarget(unittest.TestCase):
    def test_local(self):
        for url in ("http://127.0.0.1:8000", "http://localhost", "https://localhost:8443/login"):
            self.assertTrue(is_local_target(url), url)

    def test_not_local(self):
        for url in ("http://example.com", "http://127.0.0.1.evil.com",
                    "http://localhost.evil.com", "http://localhost@evil.com",
                    "http://evil.com@127.0.0.1", "ftp://127.0.0.1",
                    "127.0.0.1:8000", "", None):
            self.assertFalse(is_local_target(url), url)


if __name__ == "__main__":
    unittest.main()
