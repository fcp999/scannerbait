"""Drive client_address() with synthetic requests to prove the header choice.

Runs inside the container so it imports the deployed scannerbait module
exactly as it is, rather than a copy.
"""
import sys

sys.path.insert(0, "/app")

import scannerbait as m


class FakeHeaders:
    def __init__(self, items):
        # items is a list of (name, value) preserving duplicates, which is the
        # whole point: a dict would collapse them the way .get() does.
        self._items = items

    def get(self, name, default=""):
        for k, v in self._items:
            if k.lower() == name.lower():
                return v
        return default

    def getlist(self, name):
        return [v for k, v in self._items if k.lower() == name.lower()]


class FakeRequest:
    def __init__(self, remote_addr, headers):
        self.remote_addr = remote_addr
        self.headers = FakeHeaders(headers)


def run(label, remote_addr, headers, expected):
    m.request = FakeRequest(remote_addr, headers)
    got = m.client_address()
    ok = "PASS" if got == expected else "FAIL"
    print(f"{ok}  {label}")
    print(f"      peer={remote_addr}  headers={headers}")
    print(f"      got={got}  expected={expected}")
    return got == expected


print("trusted list:", [str(n) for n in m.TRUSTED_PROXIES])
print()

results = []

# The attack from Fred's capture: scanner sends its own XFF, HAProxy appends
# the real client in a second header. The real one carries ::ffff:.
results.append(run(
    "ha-proxy chain, scanner spoofs first header",
    "192.168.0.209",
    [("X-Forwarded-For", "192.168.1.1"),
     ("X-Forwarded-For", "::ffff:93.123.109.164")],
    "93.123.109.164"))

# Same shape, spoofed value is a private address the scanner picked to look
# like it came from inside the LAN.
results.append(run(
    "ha-proxy chain, spoof looks internal",
    "192.168.0.209",
    [("X-Forwarded-For", "10.0.0.1"),
     ("X-Forwarded-For", "::ffff:93.123.109.164")],
    "93.123.109.164"))

# Clean request through the proxy: only HAProxy's header present.
results.append(run(
    "ha-proxy chain, no spoof",
    "192.168.0.209",
    [("X-Forwarded-For", "::ffff:93.123.109.164")],
    "93.123.109.164"))

# Genuine IPv6 client, not v4-mapped: must stay native, not be mangled.
results.append(run(
    "ha-proxy chain, genuine ipv6 client",
    "192.168.0.209",
    [("X-Forwarded-For", "::ffff:8.8.8.8")],
    "8.8.8.8"))

# No header at all: fall back to the peer.
results.append(run(
    "no header, trusted peer",
    "192.168.0.209",
    [],
    "192.168.0.209"))

# Malformed header: never inject text into the log, fall back to peer.
results.append(run(
    "malformed header",
    "192.168.0.209",
    [("X-Forwarded-For", "not-an-ip")],
    "192.168.0.209"))

print()
print(f"{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
