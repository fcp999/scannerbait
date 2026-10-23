import json
import os
import tempfile
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
                elif path == "/.git/config":
                    # A plausible git config. It carries no literal "DECOY"
                    # marker by design: a decoy that announces itself is a
                    # worse decoy. Assert the shape instead.
                    self.assertIn(b"[core]", response.data)
                    self.assertIn(b"example.invalid", response.data)
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

    def test_terminal_decoy_defaults_to_raw_controls(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.get("/decoy/terminal.txt")
        self.assertEqual(response.data.count(b"\x07"), 80)
        self.assertIn(b"\x1b[30;40m", response.data)
        self.assertIn(b"\x1b[0m", response.data)
        self.assertIn(b'comma, quote, decoy', response.data)

    def test_terminal_decoy_can_be_set_to_literal_text(self):
        with patch.dict(os.environ, {"SCANNERBAIT_RAW_CONTROLS": "0"}):
            response = self.client.get("/decoy/terminal.txt")
        self.assertNotIn(b"\x07", response.data)
        self.assertNotIn(b"\x1b", response.data)
        self.assertIn(b"\\x07", response.data)


    def test_requests_do_not_write_an_access_log(self):
        """Logging is stdout-only; a probe must never create an on-disk log.

        The honeypot previously shared its log with a traffic generator, so a
        real attack and a fabricated one were indistinguishable. Real events
        only: nothing may be appended to disk for a request.
        """
        with tempfile.TemporaryDirectory() as tmp:
            before = set(os.listdir(tmp))
            with patch.dict(os.environ, {"SCANNERBAIT_LOG": os.path.join(tmp, "access.log")}):
                for path in ("/.env", "/admin/", "/robots.txt", "/scanner-nope"):
                    self.client.get(path)
            after = set(os.listdir(tmp))
            self.assertEqual(before, after, f"request wrote to disk: {after - before}")


class ServerNameTests(unittest.TestCase):
    """Decoys present the configured hostname, and an obvious placeholder otherwise."""

    def setUp(self):
        self.client = scannerbait.app.test_client()

    def test_decoys_use_the_configured_server_name(self):
        with patch.dict(os.environ, {"SCANNERBAIT_SERVERNAME": "intranet-dc01.example.test"}):
            with patch.object(scannerbait, "SERVERNAME", "intranet-dc01.example.test"):
                for path in ("/.git/config", "/.env", "/.ssh/config"):
                    body = self.client.get(path).data.decode()
                    self.assertIn("intranet-dc01.example.test", body, path)
                    self.assertNotIn("example.invalid", body, path)

    def test_placeholder_is_kept_when_unset(self):
        with patch.object(scannerbait, "SERVERNAME", ""):
            body = self.client.get("/.env").data.decode()
            # An obvious placeholder beats inventing a real-looking hostname.
            self.assertIn("example.invalid", body)


if __name__ == "__main__":
    unittest.main()


class SyslogShippingTests(unittest.TestCase):
    """Events ship to the collector as RFC 5424 lines, and only when configured."""

    def setUp(self):
        self.client = scannerbait.app.test_client()

    def test_event_is_shipped_as_rfc5424(self):
        received = []

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def sendall(self, data):
                received.append(data)

        with patch.dict(os.environ, {"SCANNERBAIT_SYSLOG": "127.0.0.1:514"}):
            scannerbait._SYSLOG = "127.0.0.1:514"
            scannerbait._SYSLOG_HOST = "127.0.0.1"
            scannerbait._SYSLOG_PORT = "514"
            scannerbait._SHIP_FAILED = False
            with patch("scannerbait.socket.create_connection", return_value=FakeSocket()):
                self.client.get("/.env")

        self.assertTrue(received, "expected one shipped line")
        line = received[0].decode()
        self.assertTrue(line.startswith("<14>1 "), line)
        # RFC 5424 header: syslog version 1, then timestamp, hostname and app name.
        parts = line.split(" ")
        self.assertEqual(parts[0], "<14>1")
        self.assertTrue(parts[1].endswith("Z"), f"timestamp field: {parts[1]}")
        self.assertEqual(parts[3], "scannerbait", f"app name field: {parts[3]}")
        self.assertIn('"event":"request"', line)

    def test_no_shipping_when_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            scannerbait._SYSLOG_HOST = ""
            scannerbait._SHIP_FAILED = False
            with patch("scannerbait.socket.create_connection") as connect:
                scannerbait.log_event("request", path="/.env")
            connectassert = connect.assert_not_called
            connectassert()

    def test_dead_collector_does_not_fail_the_request(self):
        """A honeypot must still answer when the log collector is down."""
        scannerbait._SYSLOG_HOST = "127.0.0.1"
        scannerbait._SYSLOG_PORT = "1"
        scannerbait._SHIP_FAILED = False
        response = self.client.get("/.env")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(scannerbait._SHIP_FAILED)


    def test_unset_syslog_does_not_ship(self):
        """No collector configured means no outbound connection is attempted."""
        with patch.dict(os.environ, {}, clear=True):
            scannerbait._SYSLOG_HOST = ""
            scannerbait._SHIP_FAILED = False
            with patch("scannerbait.socket.create_connection") as connect:
                scannerbait.log_event("request", path="/.env")
            connect.assert_not_called()
