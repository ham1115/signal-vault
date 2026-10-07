#!/usr/bin/env python3
"""
Guardrail suite: throws hostile input at the challenge and asserts that it
degrades cleanly. Nothing here should ever produce a 500 or hang the app.

    python3 tests/abuse_test.py [base_url]
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
FAILURES: list[str] = []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


def hit(path, cookie=None, data=None, headers=None, raw_body=None):
    url = f"{BASE.rstrip('/')}{path}"
    if raw_body is not None:
        body = raw_body
    else:
        body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    if cookie:
        req.add_header("Cookie", f"sv_session={cookie}")
    if raw_body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with OPENER.open(req, timeout=10) as resp:
            return resp.status, resp.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read(8192).decode("utf-8", "replace")
    except Exception as exc:  # connection reset / timeout == a crash
        return 0, repr(exc)


def check(name, condition, detail=""):
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def token(header: dict, claims: dict, key: str | None) -> str:
    dump = lambda o: json.dumps(o, separators=(",", ":"), sort_keys=True).encode()
    signing_input = f"{b64(dump(header))}.{b64(dump(claims))}"
    if key is None:
        return f"{signing_input}."
    sig = hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(sig)}"


def main() -> int:
    now = int(time.time())
    admin = {"sub": "x", "role": "admin", "clearance": "VAULT",
             "iat": now, "exp": now + 3600}

    print("\n== token forgery attempts that must NOT reach the vault ==")
    cases = [
        ("alg=none, empty signature",
         token({"alg": "none", "typ": "JWT", "kid": "legacy-dev"}, admin, None)),
        ("alg=HS256 with no signature",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"}, admin, None)),
        ("unknown kid",
         token({"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"}, admin, "x")),
        ("kid pointing at a dict lookup miss",
         token({"alg": "HS256", "typ": "JWT", "kid": "main-2027"}, admin, "x")),
        ("correct kid, wrong key",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"}, admin, "wrong")),
        ("signature stripped from a valid token",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"},
               admin, "svc-dev-rotate-me").rsplit(".", 1)[0] + ".AAAA"),
        ("expired admin token",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"},
               {**admin, "exp": now - 10}, "svc-dev-rotate-me")),
        ("exp as a string",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"},
               {**admin, "exp": "9999999999"}, "svc-dev-rotate-me")),
        ("exp as boolean True",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"},
               {**admin, "exp": True}, "svc-dev-rotate-me")),
        ("role as a list",
         token({"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"},
               {**admin, "role": ["admin"]}, "svc-dev-rotate-me")),
        ("missing kid header",
         token({"alg": "HS256", "typ": "JWT"}, admin, "svc-dev-rotate-me")),
        ("kid as an integer",
         token({"alg": "HS256", "typ": "JWT", "kid": 1}, admin, "svc-dev-rotate-me")),
        ("typ tampered",
         token({"alg": "HS256", "typ": "JWS", "kid": "legacy-dev"},
               admin, "svc-dev-rotate-me")),
    ]
    for name, candidate in cases:
        status, _ = hit("/vault", cookie=candidate)
        check(name, status in (302, 401, 403), f"got {status}")

    print("\n== malformed tokens must not raise ==")
    garbage = [
        ("empty cookie", ""),
        ("single dot", "."),
        ("two segments", "aaa.bbb"),
        ("five segments", "a.b.c.d.e"),
        ("non-base64", "!!!.@@@.###"),
        ("base64 of non-JSON", f"{b64(b'not json')}.{b64(b'also not')}.{b64(b'x')}"),
        ("JSON array header", f"{b64(b'[1,2]')}.{b64(b'{}')}.{b64(b'x')}"),
        ("null bytes", b64(b"\x00\x00").join([".", "."])),
        ("deep nesting", f"{b64(b'{\"a\":' + b'[' * 200 + b']' * 200 + b'}')}.{b64(b'{}')}.{b64(b'x')}"),
        ("oversized token", "A" * 5000),
        # Latin-1 high bytes: what a browser would actually be able to send.
        ("high-byte soup", "\xff\xfe\xfd.\xff\xfe\xfd.\xff\xfe\xfd"),
    ]
    for name, candidate in garbage:
        status, _ = hit("/console", cookie=candidate)
        check(name, status in (200, 302, 400, 401), f"got {status}")

    print("\n== injection payloads in the login form ==")
    payloads = [
        "{{7*7}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "' OR 1=1 --",
        "admin'/**/UNION/**/SELECT/**/1--",
        "../../../../flag.txt",
        "..%2f..%2fflag.txt",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "%00guest",
        "\x00\x01\x02",
        "A" * 4000,
    ]
    for payload in payloads:
        status, body = hit("/login", data={"username": payload, "password": payload})
        leaked = (
            "CTF{" in body                      # flag disclosure
            or "root:" in body                  # file read
            or "<script>alert(1)</script>" in body  # unescaped reflection
            or "<img src=x" in body
            or "Traceback" in body              # stack trace
            or "werkzeug" in body.lower()
        )
        check(f"login payload {payload[:28]!r}", status in (200, 401) and not leaked,
              f"status {status}")

    print("\n== path and method abuse ==")
    for path in ["/../flag.txt", "/vault/../../flag.txt", "/%2e%2e/flag.txt",
                 "/internal/", "/internal/support-bundle", "/static/../app.py",
                 "/console%00", "/" + "a" * 3000]:
        status, body = hit(path)
        check(f"GET {path[:40]}",
              status in (200, 301, 302, 400, 401, 403, 404, 414, 429)
              and "CTF{" not in body, f"status {status}")

    for method in ["PUT", "DELETE", "PATCH", "TRACE"]:
        req = urllib.request.Request(f"{BASE}/vault", method=method)
        try:
            with OPENER.open(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as err:
            status = err.code
        except Exception as exc:
            status = 0
        check(f"{method} /vault", status in (302, 400, 401, 403, 405, 429),
              f"got {status}")

    print("\n== oversized body ==")
    status, _ = hit("/login", raw_body=b"username=" + b"A" * (64 * 1024))
    check("64 KiB POST body rejected cleanly",
          status in (400, 401, 413, 429), f"got {status}")

    print("\n== rate limiter is alive ==")
    codes = {hit("/healthz")[0] for _ in range(40)}
    check("burst of 40 requests answered without a crash",
          codes and codes <= {200, 429}, f"codes {sorted(codes)}")

    print("\n== service still healthy afterwards ==")
    status, body = hit("/healthz")
    check("healthz answers 200 or 429, never 5xx",
          status in (200, 429), f"got {status}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURE(S): " + ", ".join(FAILURES))
        return 1
    print("all guardrail checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
