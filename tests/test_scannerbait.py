import json
import os
import tempfile
import unittest
from unittest.mock import patch

import scannerbait


MARKERS = ("DECOY", "NOT_A_REAL", "NOT A REAL", "EXAMPLE.INVALID", "SYNTHETIC",
           "INTENTIONALLY UNUSABLE", "SCANNERBAIT TEST DATA", "decoy_user")


def _self_identifies(body):
    """True when a response labels itself as fabricated."""
    text = body.decode(errors="replace").upper() if isinstance(body, bytes) else body.upper()
    return [m for m in MARKERS if m.upper() in text]


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
                    self.assertIn(b"[core]", response.data)
                    self.assertIn(b"[remote \"origin\"]", response.data)
                elif path == "/robots.txt":
                    self.assertIn(b"Disallow:", response.data)
                else:
                    # Nothing may announce itself as fake: the decoy has to look
                    # like real configuration for a scanner to spend time on it.
                    self.assertFalse(_self_identifies(response.data), path)

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

    def test_decoys_use_the_configured_domain(self):
        """Each decoy host is a distinct role under the configured domain.

        Every service collapsing onto the bare server name would not look like
        a real estate, so the label has to survive: db.<domain>, code.<domain>,
        not intranet-dc01 for all three.
        """
        with patch.object(scannerbait, "SERVERNAME", "intranet-dc01.example.test"):
            with patch.object(scannerbait, "DOMAIN", "example.test"):
                expectations = {
                    "/.git/config": "code.example.test",
                    "/.env": "db.example.test",
                    "/.ssh/config": "staging.example.test",
                }
                for path, host in expectations.items():
                    body = self.client.get(path).data.decode()
                    self.assertIn(host, body, path)
                    self.assertNotIn("example.invalid", body, path)

    def test_hosts_use_the_internal_domain(self):
        """Decoy hostnames come from the configured domain, never a placeholder."""
        with patch.object(scannerbait, "SERVERNAME", "intranet-dc01.example.test"), \
             patch.object(scannerbait, "DOMAIN", "example.test"):
            body = self.client.get("/.env").data.decode()
        self.assertIn("db.example.test", body)
        self.assertNotIn("example.invalid", body)


class ClientAddressTests(unittest.TestCase):
    """The logged address is the originating client, in a readable form."""

    def setUp(self):
        self.client = scannerbait.app.test_client()

    def _logged_ip(self, headers):
        with patch.object(scannerbait, "log_event") as log:
            self.client.get("/.env", headers=headers)
        return log.call_args.kwargs["ip"], log.call_args.args[0]

    def test_prefers_forwarded_for_over_socket_peer(self):
        ip, _ = self._logged_ip({"X-Forwarded-For": "203.0.113.7"})
        self.assertEqual(ip, "203.0.113.7")

    def test_takes_leftmost_entry_of_a_chain(self):
        ip, _ = self._logged_ip({"X-Forwarded-For": "203.0.113.7, 10.0.0.1, 10.0.0.2"})
        self.assertEqual(ip, "203.0.113.7")

    def test_ipv4_mapped_ipv6_is_unwrapped(self):
        ip, _ = self._logged_ip({"X-Forwarded-For": "::ffff:198.51.100.9"})
        self.assertEqual(ip, "198.51.100.9")

    def test_genuine_ipv6_is_preserved(self):
        ip, _ = self._logged_ip({"X-Forwarded-For": "2001:db8::1"})
        self.assertEqual(ip, "2001:db8::1")

    def test_malformed_header_falls_back_to_socket_peer(self):
        # A scanner can send its own header; it must never reach the log as text.
        ip, _ = self._logged_ip({"X-Forwarded-For": "<script>alert(1)</script>"})
        self.assertEqual(ip, "127.0.0.1")

    def test_login_probe_also_uses_the_client_address(self):
        with patch.object(scannerbait, "log_event") as log:
            self.client.get("/wp-login.php", headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(log.call_args.kwargs["ip"], "203.0.113.9")


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


# Each probe path must return the file format a target would expect. A body that
# is merely non-empty and free of markers still gets spotted instantly when the
# shape is wrong -- a kubeconfig that is JSON, a .tfvars holding variable blocks.
FORMAT_CASES = [
    ("/.env", "dotenv"),
    ("/.aws/credentials", "ini"),
    ("/.aws/config", "ini"),
    ("/.git/config", "ini"),
    ("/.git-credentials", "url"),
    ("/.ssh/config", "sshconfig"),
    ("/.ssh/id_ed25519", "openssh"),
    ("/.kube/config", "kubeconfig"),
    ("/terraform.tfvars", "tfvars"),
    ("/backend.tf", "hcl"),
    ("/clouds.yaml", "yaml"),
    ("/docker-compose.yml", "yaml"),
    ("/appsettings.json", "json"),
]


def _yaml_load(text):
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a test-only dependency
        return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def matches_format(text, kind):
    """True when ``text`` is shaped like a file of ``kind``."""
    stripped = text.strip()
    if kind == "dotenv":
        return bool(stripped) and all(
            "=" in line for line in stripped.splitlines() if line.strip() and not line.startswith("#"))
    if kind == "ini":
        lines = [l.strip() for l in stripped.splitlines() if l.strip()]
        return lines[0].startswith("[") and any(" =" in l or "=" in l for l in lines)
    if kind == "url":
        return stripped.startswith("https://") and "@" in stripped.splitlines()[0]
    if kind == "sshconfig":
        return stripped.startswith("Host ") and "HostName" in stripped
    if kind == "openssh":
        return (stripped.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
                and stripped.endswith("-----END OPENSSH PRIVATE KEY-----"))
    if kind == "kubeconfig":
        loaded = _yaml_load(text)
        return isinstance(loaded, dict) and loaded.get("kind") == "Config" \
            and {"clusters", "contexts", "users"} <= set(loaded)
    if kind == "tfvars":
        # Bare assignments (comments allowed); a variable block is the wrong file.
        if 'variable "' in stripped:
            return False
        lines = [l for l in stripped.splitlines() if l.strip() and not l.strip().startswith("#")]
        return bool(lines) and all("=" in l for l in lines)
    if kind == "hcl":
        return stripped.startswith("terraform {") or stripped.startswith("provider \"")
    if kind == "yaml":
        loaded = _yaml_load(text)
        return loaded is not None
    if kind == "json":
        import json as _json
        try:
            _json.loads(text)
        except ValueError:
            return False
        return True
    raise AssertionError("unknown format kind: " + kind)


class DecoyFormatTests(unittest.TestCase):
    """Each path returns the file shape it claims to be."""

    def setUp(self):
        self.client = scannerbait.app.test_client()

    def test_each_path_returns_its_expected_format(self):
        with patch.object(scannerbait, "SERVERNAME", "intranet-dc01.example.test"), \
             patch.object(scannerbait, "DOMAIN", "example.test"):
            for path, kind in FORMAT_CASES:
                with self.subTest(path=path, kind=kind):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200, path)
                    body = response.data.decode(errors="replace")
                    self.assertTrue(matches_format(body, kind),
                                    f"{path} is not {kind}:\n{body[:300]}")


if __name__ == "__main__":
    unittest.main()
