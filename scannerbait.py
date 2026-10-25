"""A small web honeypot that serves inert, synthetic decoys to common probes."""

import hashlib
import hmac
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
# Hostname the decoys present themselves as. A named host is more convincing
# than a placeholder, so this is operator-configurable.
SERVERNAME = os.environ.get("SCANNERBAIT_SERVERNAME", "") or ""
# Internal domain for decoy hostnames, derived from SERVERNAME so the fake
# estate looks like part of the same organisation.
DOMAIN = os.environ.get("SCANNERBAIT_DOMAIN", "") or (
    SERVERNAME.split(".", 1)[1] if "." in SERVERNAME else "fcp3.me")

# Seed for decoy credentials. Values are derived on demand rather than stored,
# so no credential ever has to be written down or passed around, and a
# redeploy with the same seed serves identical secrets.
CRED_SEED = os.environ.get("SCANNERBAIT_CRED_SEED", "") or "scannerbait-decoy-seed"
# Rotation period for decoy credentials. A credential is stable for the whole
# window, so a scanner that probes the same path twice sees the same secret and
# has no reason to think the box is inconsistent. Set to 0 to disable rotation.
CRED_ROTATE_SECONDS = int(os.environ.get("SCANNERBAIT_CRED_ROTATE_SECONDS", "86400") or 86400)
# The window a credential belongs to. Derived from the wall clock, not stored,
# so a restart mid-window keeps serving the same values.
CRED_WINDOW = int(time.time() // CRED_ROTATE_SECONDS) if CRED_ROTATE_SECONDS > 0 else 0
# Peers allowed to set X-Forwarded-For. HAProxy reaches the container through the
# published port, so it appears as the Docker host address. Anything else that
# sends the header is treated as a scanner lying about its address.
_TRUSTED_DEFAULT = "172.16.0.0/12,192.168.0.204/32,192.168.0.209/32"
TRUSTED_PROXIES = []
for _entry in (os.environ.get("SCANNERBAIT_TRUSTED_PROXY", "") or _TRUSTED_DEFAULT).split(","):
    _entry = _entry.strip()
    if not _entry:
        continue
    try:
        TRUSTED_PROXIES.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError:
        logger.warning("ignoring invalid SCANNERBAIT_TRUSTED_PROXY entry: %r", _entry)
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _rotating_seed():
    """Seed plus window, so rotation is deterministic within a 24h bucket."""
    return f"{CRED_SEED}:{CRED_WINDOW}" if CRED_WINDOW else CRED_SEED


def _digest(label, length=32):
    """Deterministic bytes for a labelled slot, keyed by the configured seed."""
    out = b""
    counter = 0
    seed = _rotating_seed()
    while len(out) < length:
        out += hmac.new(seed.encode(), f"{label}:{counter}".encode(),
                        hashlib.sha256).digest()
        counter += 1
    return out[:length]


def _b64(label, length):
    """URL-safe-ish base64 characters, the shape most secrets take."""
    import base64
    raw = base64.b64encode(_digest(label, length)).decode()
    return raw.rstrip("=")[:length]


def _hex(label, length):
    return _digest(label, length).hex()[:length]


def _alnum(label, length, alphabet=_B32):
    return "".join(alphabet[b % len(alphabet)] for b in _digest(label, length))


def cred(kind, label):
    """A decoy credential of the requested shape.

    Shapes follow the real providers so a scanner that pattern-matches against
    AWS or GitHub key formats sees something it recognises -- which is the point:
    it should want to test them.
    """
    if kind == "aws_id":
        return "AKIA" + _alnum(label, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    if kind == "aws_secret":
        return _b64(label, 40)
    if kind == "github":
        return "ghp_" + _alnum(label, 36, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if kind == "db_password":
        return _b64(label, 18) + "!" + _alnum(label + ":n", 3, "0123456789")
    if kind == "password":
        return _b64(label, 14) + "#" + _alnum(label + ":n", 2, "0123456789")
    if kind == "jwt":
        return _b64(label, 43)
    if kind == "api_key":
        return "sk_live_" + _alnum(label, 24, "abcdefghijklmnopqrstuvwxyz0123456789")
    if kind == "ssh_key":
        body = "".join(_b64(label + f":{i}", 64) for i in range(10))
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + "\n".join(lines) + "\n"
                "-----END OPENSSH PRIVATE KEY-----\n")
    return _b64(label, 24)

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


def _host(label):
    """Compose a decoy hostname under the configured domain.

    ``label`` is the role being named -- "db", "code", "vpn" -- so the estate
    reads as a set of distinct internal hosts rather than every service
    collapsing onto one name. An empty label yields the bare domain.
    """
    label = (label or "").strip(".")
    domain = DOMAIN or "fcp3.me"
    return f"{label}.{domain}" if label else domain


def client_address():
    """Caller address as IPv4 or IPv6, taken from the proxy-supplied header.

    A scanner reaches the honeypot through HAProxy, so the socket peer is the
    proxy rather than the scanner. HAProxy appends its own X-Forwarded-For
    header without rewriting one the client already sent, so a single request
    can carry several headers: the scanner's fabricated value first, the real
    client last.

    Only the last header is trusted. It is the one HAProxy wrote, and it is the
    only entry the scanner cannot control. Everything to the left of it was
    supplied by the scanner and is discarded rather than parsed.

    The last header is also preferred because it is the only one that reliably
    carries the dual-stack form: HAProxy reports the peer it accepted the
    connection from as ::ffff:a.b.c.d, which unwraps to the dotted quad an
    analyst expects to read.

    The peer must still be a trusted proxy. A direct hit on the published port
    is logged as itself, so a scanner cannot write a forged address into the
    log by addressing the container directly. Trusted peers are configured with
    SCANNERBAIT_TRUSTED_PROXY.
    """
    peer = _normalise_address(request.remote_addr)
    if peer and _is_trusted_proxy(peer):
        # getlist keeps duplicate headers; .get() returns only the first, which
        # is exactly the forged one.
        values = request.headers.getlist("X-Forwarded-For")
        if values:
            # The last header is HAProxy's; a scanner prepending its own cannot
            # displace it. Within that header take the last entry for the same
            # reason, in case a chained proxy appended to it.
            hops = [h.strip() for h in values[-1].split(",") if h.strip()]
            if hops:
                address = _normalise_address(hops[-1])
                if address:
                    return address
    return peer or "-"


def _is_trusted_proxy(address):
    """True when ``address`` is a proxy allowed to set X-Forwarded-For."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in TRUSTED_PROXIES)


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
    """Return fabricated data for common secret/config probes; never read local files.

    Every value is shaped like the real thing: provider-accurate key formats,
    internal-looking hostnames, consistent IDs. Nothing in a response labels
    itself as fake, because a decoy that announces itself only wastes one
    request. Credentials are derived from the configured seed, so they are
    stable across requests without any secret being stored or transmitted.
    """
    normalized = path.lower().rstrip("/") or "/"
    leaf = normalized.rsplit("/", 1)[-1]

    if normalized == "/robots.txt":
        return ("User-agent: *\nDisallow: /admin/\nDisallow: /internal/\n"
                "Disallow: /backup/\nSitemap: https://" + _host("www") + "/sitemap.xml\n",
                "text/plain", 200)

    if normalized in ("/.git/config", "/.gitconfig") or normalized.endswith("/.git/config"):
        return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                "\tlogallrefupdates = true\n"
                "[remote \"origin\"]\n\turl = https://" + _host("code") + "/bof/portal.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
                "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
                "[user]\n\tname = Build Bot\n\temail = buildbot@" + DOMAIN + "\n",
                "text/plain", 200)

    if normalized.endswith("/.git-credentials"):
        return ("https://buildbot:" + cred("github", "git:cred") + "@" + _host("code") + "\n",
                "text/plain", 200)

    if (normalized.startswith("/.ssh/") or leaf in {
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "private.key", "key.pem", ".pem", ".ppk"
    } or leaf.endswith((".pem", ".ppk", ".key"))):
        if leaf in {"config", "known_hosts", "known_hosts.old", "authorized_keys"}:
            return ("Host " + _host("staging") + "\n"
                    "  HostName 10.20.4.18\n  User deploy\n"
                    "  IdentityFile ~/.ssh/id_ed25519\n  StrictHostKeyChecking accept-new\n"
                    "\nHost " + _host("git") + "\n  HostName 10.20.4.21\n  User git\n",
                    "text/plain", 200)
        return cred("ssh_key", "ssh:key:" + leaf), "text/plain", 200

    if normalized in ("/etc/passwd", "/etc/shadow") or normalized.endswith("/etc/passwd"):
        return ("root:x:0:0:root:/root:/bin/bash\n"
                "webapp:x:1001:1001:Web App:/srv/web:/usr/sbin/nologin\n"
                "backup:x:1002:1002:Backup:/var/backups:/usr/sbin/nologin\n"
                "deploy:x:1003:1003:Deploy:/home/deploy:/bin/bash\n",
                "text/plain", 200)

    if ".env" in leaf or (leaf in {"credentials", "credentials.json", "credentials.yml", "credentials.yaml",
                                 "secrets.yml", "secrets.yaml", "secret.yaml", "database.yml", "database.yaml"}
                          and "/.aws/" not in normalized):
        return ("APP_NAME=BankPortal\nAPP_ENV=production\n"
                "DB_HOST=" + _host("db") + "\n"
                "DB_USER=portal_readonly\nDB_PASSWORD=" + cred("db_password", "env:db") + "\n"
                "AWS_ACCESS_KEY_ID=" + cred("aws_id", "env:aws") + "\n"
                "AWS_SECRET_ACCESS_KEY=" + cred("aws_secret", "env:aws") + "\n"
                "JWT_SECRET=" + cred("jwt", "env:jwt") + "\n"
                "STRIPE_KEY=" + cred("api_key", "env:stripe") + "\n",
                "text/plain", 200)

    if leaf.endswith((".sqlite", ".sqlite3", ".db")):
        return ("BEGIN TRANSACTION;\n"
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                "password_hash TEXT, role TEXT, created_at TEXT);\n"
                "INSERT INTO users VALUES(1,'svc_portal','" + cred("password", "db:svc") +
                "','admin','2025-11-03 09:14:22');\n"
                "INSERT INTO users VALUES(2,'j.harris','" + cred("password", "db:jharris") +
                "','staff','2025-12-18 16:02:51');\n"
                "COMMIT;\n", "text/plain", 200)

    if "aws" in normalized or ".aws/" in normalized or leaf == "boto.cfg":
        return ("[default]\n"
                "aws_access_key_id = " + cred("aws_id", "aws:default") + "\n"
                "aws_secret_access_key = " + cred("aws_secret", "aws:default") + "\n"
                "region = us-east-1\n\n"
                "[profile backup]\n"
                "aws_access_key_id = " + cred("aws_id", "aws:backup") + "\n"
                "aws_secret_access_key = " + cred("aws_secret", "aws:backup") + "\n"
                "region = us-east-1\n", "text/plain", 200)

    if any(x in normalized for x in ("google", "gcp", "firebase", "azure", "azuread", "aliyun")):
        body = {"type": "service_account", "project_id": "bank-portal-prod",
                "private_key_id": _hex("gcp:keyid", 40),
                "private_key": cred("ssh_key", "gcp:pk"),
                "client_email": "portal-sa@bank-portal-prod.iam.gserviceaccount.com",
                "client_id": "104728391055271836442",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "client_secret": cred("jwt", "gcp:secret")}
        return json.dumps(body, indent=2), "application/json", 200

    if any(x in normalized for x in ("vpn", "wireguard", "openvpn", "tailscale", "zerotier", "xray",
                                      "v2ray", "trojan", "sing-box", "shadowsocks", "hysteria", "clash",
                                      "ipsec", "ikev2", "globalprotect", "anyconnect", "forti", "zscaler",
                                      "mullvad", "surfshark", "protonvpn", "strongvpn", "symantec", "duo",
                                      "okta", "keycloak", "sophos", "sonicwall", "watchguard", "juniper",
                                      "netskope", "netmotion", "pulse", "barracuda", "citrix", "cisco",
                                      "checkpoint", "paloalto", "forcepoint", "pritunl", "softether")):
        return ("client\n"
                "dev tun\n"
                "proto udp\n"
                "remote " + _host("vpn") + " 1194\n"
                "resolv-retry infinite\n"
                "nobind\n"
                "persist-key\n"
                "persist-tun\n"
                "auth-user-pass\n"
                "remote-cert-tls server\n"
                "cipher AES-256-GCM\n"
                "auth SHA256\n"
                "<ca>\n" + cred("ssh_key", "vpn:ca") + "</ca>\n",
                "text/plain", 200)

    if "kubeconfig" in normalized or leaf in {"config", "kubeconfig"} and ".kube" in normalized:
        # A real kubeconfig is YAML with base64 blobs, not a JSON credentials blob.
        return ("apiVersion: v1\n"
                "kind: Config\n"
                "clusters:\n"
                "- cluster:\n"
                "    certificate-authority-data: " + _b64("kube:ca", 88) + "\n"
                "    server: https://k8s." + DOMAIN + ":6443\n"
                "  name: bankportal-prod\n"
                "contexts:\n"
                "- context:\n"
                "    cluster: bankportal-prod\n"
                "    user: deployer\n"
                "    namespace: portal\n"
                "  name: bankportal-prod\n"
                "current-context: bankportal-prod\n"
                "preferences: {}\n"
                "users:\n"
                "- name: deployer\n"
                "  user:\n"
                "    client-certificate-data: " + _b64("kube:cert", 88) + "\n"
                "    client-key-data: " + _b64("kube:key", 88) + "\n",
                "application/yaml", 200)

    if leaf == ".tfvars" or normalized.endswith(".tfvars"):
        # A .tfvars file is bare assignments. variable blocks belong in a .tf
        # file; putting them here is a tell that the file was never real.
        return ("# production estate, eu-west-1\n"
                "db_password   = \"" + cred("db_password", "tf:db") + "\"\n"
                "api_token     = \"" + cred("api_key", "tf:api") + "\"\n"
                "aws_region    = \"us-east-1\"\n"
                "instance_type = \"m6i.xlarge\"\n",
                "text/plain", 200)

    if "terraform" in normalized or "backend.tf" in normalized:
        return ("terraform {\n"
                "  required_version = \">= 1.6.0\"\n"
                "  backend \"s3\" {\n"
                "    bucket         = \"bankportal-tfstate\"\n"
                "    key            = \"prod/network/terraform.tfstate\"\n"
                "    region         = \"us-east-1\"\n"
                "    dynamodb_table = \"bankportal-tflock\"\n"
                "  }\n"
                "}\n\n"
                "provider \"aws\" {\n  region = var.aws_region\n}\n",
                "text/plain", 200)

    if "clouds.yaml" in normalized:
        return ("clouds:\n"
                "  openstack:\n"
                "    auth:\n"
                "      auth_url: https://identity." + DOMAIN + ":5000/v3\n"
                "      username: portal-automation\n"
                "      password: " + cred("password", "os:password") + "\n"
                "      project_name: portal-prod\n"
                "      user_domain_name: Default\n"
                "    region_name: RegionOne\n",
                "application/yaml", 200)

    if normalized in ("/docker-compose.yml", "/compose.yml", "/compose.yaml", "/docker-compose.override.yml"):
        return ("services:\n  portal:\n    image: " + _host("registry") + "/bof/portal:1.4.2\n"
                "    environment:\n      DB_HOST: " + _host("db") + "\n"
                "      DB_PASSWORD: " + cred("db_password", "compose:db") + "\n"
                "      REDIS_URL: redis://cache." + DOMAIN + ":6379/0\n",
                "text/yaml", 200)

    if normalized in ("/appsettings.json", "/application.json", "/web.config") or leaf in {
        "appsettings.json", "application.properties", "application.yml", "application.yaml", "wrangler.toml",
        "vercel.json", "netlify.toml", "fly.toml", "render.yaml"
    }:
        body = {"ConnectionStrings": {
                    "Default": "Host=" + _host("db") + ";Database=portal;Username=portal_app;"
                               "Password=" + cred("db_password", "appsettings:db")},
                "ApiKey": cred("api_key", "appsettings:api"),
                "Environment": "Production"}
        return json.dumps(body, indent=2), "application/json", 200

    if "mcp" in normalized or "api" in normalized:
        body = {"status": "ok", "service": "portal-api", "version": "1.4.2",
                "request_id": _hex("api:reqid", 16),
                "build": "2026.10.14-3f8a91c"}
        return json.dumps(body), "application/json", 200

    # Generic but plausible synthetic data for secret/config-looking paths.
    if (any(x in normalized for x in ("secret", "credential", "token", "identity", "config", "key", "auth",
                                      "vault", "database", "mysql", "service-account", "passwd", "kubeconfig"))
            or leaf.endswith((".conf", ".cfg", ".json", ".yaml", ".yml", ".toml", ".ini", ".ovpn",
                              ".tfstate", ".tfvars", ".properties", ".xml"))):
        body = {"status": "ok", "source": "backup",
                "username": "svc_backup",
                "password": cred("password", "generic:pw"),
                "token": cred("jwt", "generic:token"),
                "endpoint": "https://" + _host("api")}
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
