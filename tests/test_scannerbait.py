import json
import os
import unittest
from unittest.mock import patch

import scannerbait


class ScannerbaitTests(unittest.TestCase):
    def setUp(self):
        self.client = scannerbait.app.test_client()

    def test_sampled_paths_get_synthetic_decoys(self):
        for path in ("/robots.txt", "/.env", "/.aws/credentials", "/.git/config",
                     "/etc/passwd", "/zscaler.conf", "/tailscale.conf", "/xray.json",
                     "/terraform.tfvars", "/docker-compose.yml", "/db.sqlite", "/duo", "/okta.yaml"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.data)
                if path == "/robots.txt":
                    self.assertIn(b"Disallow:", response.data)
                elif path == "/etc/passwd":
                    self.assertIn(b"webapp:", response.data)
                else:
                    self.assertIn(b"DECOY", response.data.upper())

    def test_unknown_path_is_not_reflected(self):
        response = self.client.get("/scanner-nope?x=<script>")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"<script>", response.data)

    def test_password_is_not_logged(self):
        body = scannerbait.format_event("login_probe", username='x\n\x1b[31m', password_length=8)
        self.assertNotIn("\x1b", body)
        self.assertNotIn("\n", body)
        self.assertEqual(json.loads(body)["password_length"], 8)

    def test_terminal_decoy_is_literal_by_default(self):
        with patch.dict(os.environ, {"SCANNERBAIT_RAW_CONTROLS": "0"}):
            response = self.client.get("/decoy/terminal.txt")
        self.assertNotIn(b"\x07", response.data)
        self.assertNotIn(b"\x1b", response.data)
        self.assertIn(b"\\x07", response.data)
        self.assertIn(b'comma, quote, decoy', response.data)

    def test_terminal_decoy_raw_mode_is_opt_in(self):
        with patch.dict(os.environ, {"SCANNERBAIT_RAW_CONTROLS": "1"}):
            response = self.client.get("/decoy/terminal.txt")
        self.assertEqual(response.data.count(b"\x07"), 8)
        self.assertIn(b"\x1b[30;40m", response.data)
        self.assertIn(b"\x1b[0m", response.data)


if __name__ == "__main__":
    unittest.main()
