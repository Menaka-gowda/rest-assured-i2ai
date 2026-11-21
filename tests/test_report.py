"""Unit tests for report generator (ME-3, ME-5, ME-6)."""

import os
import shutil
import tempfile
import unittest

from recon.base import make_result
from report.generator import generate_markdown_report, generate_html_report, save_reports


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.mock_results = [
            make_result("security_headers", "http://127.0.0.1:8000", "fail", "medium", "Missing CSP and HSTS."),
            make_result("metadata_disclosure", "http://127.0.0.1:8000", "fail", "medium", "Apache banner leaked."),
            make_result("caching_and_csrf", "http://127.0.0.1:8000", "warn", "medium", "Plain HTTP form submit."),
            make_result("ai_conversational_endpoint", "http://127.0.0.1:8000", "fail", "high", "Prompt override key leaked."),
            make_result("anomalous_origin", "http://127.0.0.1:8000", "simulated", "low", "Simulated origin returned 403.")
        ]

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_markdown_report_structure(self):
        md = generate_markdown_report("http://127.0.0.1:8000", self.mock_results)
        self.assertIn("# Executive Reconnaissance & Security Assurance Report", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Assessment Scorecard", md)
        self.assertIn("## 3. Detailed Audit Findings", md)
        self.assertIn("## 4. Methodological Distinction: Observation vs. Inference", md)
        self.assertIn("## 5. Scope & Localhost Boundaries", md)

    def test_html_report_structure(self):
        html = generate_html_report("http://127.0.0.1:8000", self.mock_results)
        self.assertIn("<title>Reconnaissance & Security Assurance Report</title>", html)
        self.assertIn("security_headers", html)
        self.assertIn("Observation vs. Inference Analysis", html)

    def test_save_reports(self):
        md_path, html_path = save_reports("http://127.0.0.1:8000", self.mock_results, output_dir=self.temp_dir)
        self.assertTrue(os.path.exists(md_path))
        self.assertTrue(os.path.exists(html_path))
        self.assertGreater(os.path.getsize(md_path), 500)
        self.assertGreater(os.path.getsize(html_path), 500)


if __name__ == "__main__":
    unittest.main()
