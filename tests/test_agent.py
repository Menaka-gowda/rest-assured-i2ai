"""Unit tests for ReconAgent and tool-calling execution (ME-2, ME-5)."""

import threading
import time
import unittest
from http.server import HTTPServer

from agent.agent import (
    ReconAgent,
    check_security_headers,
    check_metadata_disclosure,
    check_caching_csrf,
    check_ai_conversational_endpoint,
    check_anomalous_origin,
)
from mockbank.server import MockBankHandler, DEFAULT_HOST
from recon.base import validate_result

TEST_PORT = 8992
BASE_URL = f"http://{DEFAULT_HOST}:{TEST_PORT}"


class TestReconAgent(unittest.TestCase):
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

    def test_refuses_non_localhost_target(self):
        # Safety requirement: any non-local target must return an error
        agent = ReconAgent(target_url="http://example.com")
        data = agent.run()
        self.assertEqual(len(data["results"]), 1)
        res = data["results"][0]
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["severity"], "high")
        validate_result(res)

    def test_individual_tools_return_valid_contract(self):
        for tool_fn in (check_security_headers, check_metadata_disclosure, check_caching_csrf, check_ai_conversational_endpoint, check_anomalous_origin):
            res = tool_fn(BASE_URL)
            self.assertIsInstance(res, dict)
            # Must satisfy all contract validation rules
            validate_result(res)

    def test_end_to_end_agent_execution(self):
        agent = ReconAgent(target_url=BASE_URL)
        data = agent.run()
        self.assertGreaterEqual(len(data["results"]), 4)
        self.assertGreaterEqual(len(data["trace"]), 4)

        # Every result must be valid
        for r in data["results"]:
            validate_result(r)

        # Verify trace has thought, action, observation
        for step in data["trace"]:
            self.assertIn("thought", step)
            self.assertIn("action", step)
            self.assertIn("observation", step)


if __name__ == "__main__":
    unittest.main()
