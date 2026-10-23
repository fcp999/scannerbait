"""A small web honeypot that serves inert, synthetic decoys to common probes."""

import ipaddress
import json
import logging
import os
import socket
import sys
import time
from flask import Flask, Response, request

app = Flask(__name__)
logger = logging.getLogger("scannerbait")
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.propagate = False
# Keep Werkzeug's access log from printing attacker-controlled request lines.
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def format_event(event, **fields):
    """JSON encoding keeps control characters from becoming real log controls."""
    return json.dumps({"event": event, **fields}, ensure_ascii=True, separators=(",", ":"))


def log_event(event, **fields):
    body = format_event(event, **fields)
    logger.info(body)
    _ship(body)


# Shipping is best-effort and must never fail a request: a scanner that gets a
# 500 because the log collector is down is a scan we no longer observe.
# Hostname the decoys present themselves as. Decoys that name a host are more
# convincing than ones naming example.invalid, so this is operator-configurable.
SERVERNAME = os.environ.get("SCANNERBAIT_SERVERNAME", "") or ""

_SYSLOG = os.environ.get("SCANNERBAIT_SYSLOG", "")
_SYSLOG_HOST, _, _SYSLOG_PORT = _SYSLOG.partition(":")
_SHIP_FAILED = False


def _ship(body):
    """Forward one event to syslog over TCP, in RFC 5424 form.

    The app name is fixed so the collector can label this feed distinctly from
    the router and host feeds already arriving on the same port.
    """
    global _SHIP_FAILED
    if not _SYSLOG_HOST or _SHIP_FAILED:
        return
    try:
        port = int(_SYSLOG_PORT or 514)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        host = socket.gethostname() or "-"
        # PRI 14 = facility user(1)*8 + severity info(6)
        line = f"<14>1 {stamp} {host} scannerbait - - - {body}\n"
        with socket.create_connection((_SYSLOG_HOST, port), timeout=1.0) as conn:
            conn.sendall(line.encode("utf-8", "replace"))
    except OSError:
        # Log once, then stay quiet so a dead collector cannot fill stdout.
        if not _SHIP_FAILED:
            _SHIP_FAILED = True
            logger.warning(format_event("syslog_ship_failed", target=_SYSLOG))


def _host(default):
    """Configured server name, or the given placeholder when unset.

    Decoy bodies name a host that looks like the organisation's own; when the
    operator has not configured one the .invalid placeholder is kept, because
    inventing a real-looking name is worse than an obvious placeholder.
    """
    return SERVERNAME or default


def client_address():
    """Caller address as IPv4 or IPv6, preferring X-Forwarded-For.

    Behind HAProxy the socket peer is the proxy, not the scanner, so the real
    address arrives in X-Forwarded-For. The header is a comma-separated chain
    (client, proxy1, proxy2); the left-most entry is the originator and the one
    worth logging.

    The value is untrusted: a scanner can send its own X-Forwarded-For. It is
    therefore validated as an IP literal and otherwise falls back to the socket
    peer, so a spoofed or malformed header can never inject arbitrary text into
    the log.

    IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unwrapped to plain dotted
    quad, because that is what a dual-stack listener reports and what an analyst
    expects to read. Genuine IPv6 stays in its native form.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    for candidate in (forwarded.split(",")[0].strip() if forwarded else "", request.remote_addr):
        address = _normalise_address(candidate)
        if address:
            return address
    return request.remote_addr or "-"


def _normalise_address(value):
    """Return a clean textual IP for ``value``, or None when it is not one."""
    if not value:
        return None
    text = value.strip()
    # Tolerate the bracketed host:port form some proxies emit for IPv6.
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def decoy_response(path):
    """Return inert fake data for common secret/config probes; never read local files."""
    normalized = path.lower().rstrip("/") or "/"
    leaf = normalized.rsplit("/", 1)[-1]

    if normalized == "/robots.txt":
        return ("User-agent: *\nDisallow: /admin/\nDisallow: /.well-known/internal/\n"
                "Disallow: /backup/\n", "text/plain", 200)

    if normalized in ("/.git/config", "/.gitconfig") or normalized.endswith("/.git/config"):
        return ("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                "\t[remote \"origin\"]\n\turl = https://" + _host("code.example.invalid") + "/bof/portal.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n", "text/plain", 200)

    if normalized.endswith("/.git-credentials"):
        return ("https://buildbot:DECOY_ONLY_NOT_A_TOKEN@" + _host("code.example.invalid") + "\n",
                "text/plain", 200)

    if (normalized.startswith("/.ssh/") or leaf in {
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "private.key", "key.pem", ".pem", ".ppk"
    } or leaf.endswith((".pem", ".ppk", ".key"))):
        if leaf in {"config", "known_hosts", "known_hosts.old", "authorized_keys"}:
            return ("# Synthetic SSH decoy; no usable keys\nHost " + _host("staging.example.invalid") + "\n"
                    "  HostName 192.0.2.44\n  User deploy\n", "text/plain", 200)
        return ("-----BEGIN DECOY PRIVATE KEY-----\nNOT A REAL KEY - SCANNERBAIT TEST DATA\n"
                "-----END DECOY PRIVATE KEY-----\n", "text/plain", 200)

    if normalized in ("/etc/passwd", "/etc/shadow") or normalized.endswith("/etc/passwd"):
        return ("root:x:0:0:root:/root:/bin/bash\nwebapp:x:1001:1001:Web App:/srv/web:/usr/sbin/nologin\n"
                "backup:x:1002:1002:Backup:/var/backups:/usr/sbin/nologin\n", "text/plain", 200)

    if ".env" in leaf or leaf in {"credentials", "credentials.json", "credentials.yml", "credentials.yaml",
                                 "secrets.yml", "secrets.yaml", "secret.yaml", "database.yml", "database.yaml"}:
        return ("APP_NAME=BankPortal\nAPP_ENV=production\nDB_HOST=" + _host("db.example.invalid") + "\n"
                "DB_USER=portal_readonly\nDB_PASSWORD=DECOY_ONLY_NOT_A_PASSWORD\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=DECOY_ONLY_NOT_A_CREDENTIAL\n"
                "JWT_SECRET=DECOY_ONLY_NOT_A_SECRET\n", "text/plain", 200)

    if leaf.endswith((".sqlite", ".sqlite3", ".db")):
        return ("-- Synthetic database decoy; not a SQLite database\n"
                "CREATE TABLE users (id INTEGER, username TEXT, password TEXT);\n"
                "INSERT INTO users VALUES (1, 'decoy_user', 'DECOY_ONLY_NOT_A_PASSWORD');\n",
                "text/plain", 200)

    if "aws" in normalized or ".aws/" in normalized or leaf == "boto.cfg":
        body = ("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = DECOY_ONLY_NOT_A_CREDENTIAL\n"
                "region = us-east-1\n")
        return body, "text/plain", 200

    if any(x in normalized for x in ("google", "gcp", "firebase", "azure", "azuread", "aliyun")):
        body = {"type": "service_account", "project_id": "bank-portal-decoy",
                "client_email": "scannerbait@example.invalid", "private_key_id": "DECOY_ONLY",
                "private_key": "NOT_A_REAL_PRIVATE_KEY", "client_secret": "DECOY_ONLY_NOT_A_SECRET"}
        return json.dumps(body, indent=2), "application/json", 200

    if any(x in normalized for x in ("vpn", "wireguard", "openvpn", "tailscale", "zerotier", "xray",
                                      "v2ray", "trojan", "sing-box", "shadowsocks", "hysteria", "clash",
                                      "ipsec", "ikev2", "globalprotect", "anyconnect", "forti", "zscaler",
                                      "mullvad", "surfshark", "protonvpn", "strongvpn", "symantec", "duo",
                                      "okta", "keycloak", "sophos", "sonicwall", "watchguard", "juniper",
                                      "netskope", "netmotion", "pulse", "barracuda", "citrix", "cisco",
                                      "checkpoint", "paloalto", "forcepoint", "pritunl", "softether")):
        return ("# Synthetic VPN profile; credentials and keys are intentionally unusable\n"
                "server = 198.51.100.23\nport = 1194\nusername = decoy_user\n"
                "password = DECOY_ONLY_NOT_A_PASSWORD\nprivate_key = NOT_A_REAL_PRIVATE_KEY\n",
                "text/plain", 200)

    if any(x in normalized for x in ("terraform", ".tfvars", "backend.tf", "clouds.yaml", "kubeconfig")):
        body = ("# Synthetic infrastructure decoy\nprovider \"aws\" {\n  region = \"us-east-1\"\n}\n"
                "variable \"api_token\" { default = \"DECOY_ONLY_NOT_A_TOKEN\" }\n")
        return body, "text/plain", 200

    if normalized in ("/docker-compose.yml", "/compose.yml", "/compose.yaml", "/docker-compose.override.yml"):
        return ("services:\n  portal:\n    image: registry.example.invalid/bof/portal:1.4\n"
                "    environment:\n      DB_HOST: db.example.invalid\n"
                "      DB_PASSWORD: DECOY_ONLY_NOT_A_PASSWORD\n", "text/yaml", 200)

    if normalized in ("/appsettings.json", "/application.json", "/web.config") or leaf in {
        "appsettings.json", "application.properties", "application.yml", "application.yaml", "wrangler.toml",
        "vercel.json", "netlify.toml", "fly.toml", "render.yaml"
    }:
        body = {"ConnectionStrings": {"Default": "Host=db.example.invalid;Password=DECOY_ONLY"},
                "ApiKey": "DECOY_ONLY_NOT_A_KEY", "Environment": "Production-Decoy"}
        return json.dumps(body, indent=2), "application/json", 200

    if "mcp" in normalized or "api" in normalized:
        body = {"status": "ok", "service": "portal-api", "version": "1.4.2",
                "request_id": "decoy-7f3a91", "message": "Synthetic scannerbait response"}
        return json.dumps(body), "application/json", 200

    # Generic but plausible synthetic data for secret/config-looking paths.
    if (any(x in normalized for x in ("secret", "credential", "token", "identity", "config", "key", "auth",
                                      "vault", "database", "mysql", "service-account", "passwd", "kubeconfig"))
            or leaf.endswith((".conf", ".cfg", ".json", ".yaml", ".yml", ".toml", ".ini", ".ovpn",
                              ".tfstate", ".tfvars", ".properties", ".xml"))):
        body = {"status": "ok", "source": "backup", "username": "decoy_service",
                "password": "DECOY_ONLY_NOT_A_PASSWORD", "token": "DECOY_ONLY_NOT_A_TOKEN",
                "endpoint": "https://service.example.invalid"}
        return json.dumps(body, indent=2), "application/json", 200

    return "Not found\n", "text/plain", 404


def terminal_decoy():
    """A terminal/logging test payload on a dedicated route; raw controls default on."""
    raw = os.getenv("SCANNERBAIT_RAW_CONTROLS", "1").lower() in {"1", "true", "yes", "on"}
    lines = [
        '2026-10-23 09:41:03 INFO account="guest", action="login", note="comma, quote, decoy"',
        "2026-10-23 09:41:04 WARN scanner probe captured",
    ]
    if raw:
        body = "\x07" * 80 + "\n" + "\x1b[30;40mBLACK ON BLACK DECOY\x1b[0m\n" + "\n".join(lines) + "\n"
    else:
        body = r"\x07" * 80 + "\n" + r"\x1b[30;40mBLACK ON BLACK DECOY\x1b[0m\n" + "\n".join(lines) + "\n"
    return Response(body, status=200, content_type="text/plain; charset=utf-8")


@app.route("/", methods=["GET", "HEAD"])
def index():
    log_event("request", ip=client_address(), method=request.method, path=request.path, outcome="home")
    return Response("<html><title>Bank of Florida</title><h1>Welcome to Bank of Florida</h1></html>",
                    content_type="text/html; charset=utf-8")


@app.route("/<path:path>", methods=["GET", "POST", "HEAD", "OPTIONS"])
def catch_all(path):
    normalized = "/" + path
    if normalized == "/decoy/terminal.txt":
        log_event("request", ip=client_address(), method=request.method, path=request.path, outcome="terminal_decoy")
        return terminal_decoy()

    if normalized in {"/login", "/admin", "/admin/login.asp", "/wp-login.php", "/search"}:
        form = request.form
        # Never store passwords. User-controlled fields are JSON-escaped in logs.
        log_event("login_probe", ip=client_address(), path=request.path,
                  username=form.get("user", form.get("log", ""))[:120],
                  password_length=len(form.get("pass", form.get("pwd", ""))))
        if request.method == "GET":
            return Response("<html><title>Staff Sign In</title><form method='post'>"
                            "<input name='user'><input name='pass' type='password'>"
                            "<button>Sign in</button></form></html>",
                            content_type="text/html; charset=utf-8")
        return Response("Invalid credentials\n", status=200, content_type="text/plain; charset=utf-8")

    if normalized == "/product":
        log_event("request", ip=client_address(), method=request.method, path=request.path,
                  outcome="product_probe", query_keys=sorted(request.args.keys()))
        return Response("Product unavailable\n", status=404, content_type="text/plain; charset=utf-8")

    body, content_type, status = decoy_response(normalized)
    log_event("request", ip=client_address(), method=request.method, path=request.path,
              outcome="decoy" if status == 200 else "not_found", status=status)
    return Response(body, status=status, content_type=content_type + "; charset=utf-8")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "80")))
