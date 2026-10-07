"""
Signal Vault -- Web Exploitation CTF challenge (intermediate).

Vulnerability class: JWT manipulation.

The verifier resolves the HMAC key from the attacker-controlled ``kid``
header against a key inventory that still contains a deprecated development
key. That key is leaked by a forgotten internal support-bundle endpoint, so a
player can forge an administrator token and reach the vault.

Everything is stdlib + Flask: no external auth library, no database engine,
no network egress, no writable state on disk.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from functools import wraps

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.exceptions import HTTPException

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

APP_VERSION = "2.4.1"
COOKIE_NAME = "sv_session"
TOKEN_TTL_SECONDS = 3600

# Hard caps -- see README "Guardrails".
MAX_TOKEN_BYTES = 1024
MAX_SEGMENT_BYTES = 4096
MAX_CONTENT_LENGTH = 16 * 1024
MAX_FIELD_LENGTH = 128
MAX_TRACKED_CLIENTS = 2048


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


# Per-client request budget. Generous enough for browsing and for a scripted
# solver, tight enough that a fuzzer cannot saturate the laptop. Tune with
# CTF_RATE_LIMIT / CTF_RATE_WINDOW if a venue NATs its players behind one IP.
RATE_LIMIT_REQUESTS = _int_env("CTF_RATE_LIMIT", 240, 10, 10000)
RATE_LIMIT_WINDOW = _int_env("CTF_RATE_WINDOW", 60, 1, 3600)


def _load_flag() -> str:
    """Read the flag once, at boot, from the environment or a read-only file."""
    value = os.environ.get("CTF_FLAG", "").strip()
    if value:
        return value

    for path in ("/flag.txt", "/app/flag.txt"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError:
            continue
        if value:
            return value

    return "CTF{flag_was_not_configured_see_README}"


FLAG = _load_flag()

ACTIVE_KID = "main-2026"
LEGACY_KID = "legacy-dev"

# The active key is random per container boot, so it cannot be brute forced
# or carried over from a previous round. The legacy key is the intended path.
SIGNING_KEYS = {
    ACTIVE_KID: os.environ.get("CTF_MAIN_KEY") or secrets.token_urlsafe(48),
    LEGACY_KID: os.environ.get("CTF_LEGACY_KEY", "svc-dev-rotate-me"),
}

# In-memory only. Nothing a player submits is ever persisted.
USERS = {
    "guest": {
        "password": "guest",
        "role": "analyst",
        "display": "Guest Analyst",
        "clearance": "OPEN",
    },
    "r.mendoza": {
        # Unguessable on purpose: the password is not the intended path.
        "password": secrets.token_urlsafe(32),
        "role": "admin",
        "display": "R. Mendoza",
        "clearance": "VAULT",
    },
}

FEED_ITEMS = [
    {
        "id": "SV-1041",
        "band": "VHF 148.220 MHz",
        "origin": "Relay Kilo",
        "classification": "OPEN",
        "summary": "Repeating 11-tone burst, 40 s period. Correlates with tide tables.",
    },
    {
        "id": "SV-1042",
        "band": "HF 8.992 MHz",
        "origin": "Relay Juliet",
        "classification": "OPEN",
        "summary": "Voice fragment, heavily clipped. Operator logged as weather chatter.",
    },
    {
        "id": "SV-1043",
        "band": "UHF 402.750 MHz",
        "origin": "Relay Foxtrot",
        "classification": "OPEN",
        "summary": "Telemetry downlink, unregistered NORAD ID. Flagged for review.",
    },
    {
        "id": "SV-1044",
        "band": "SHF 2.401 GHz",
        "origin": "Relay Echo",
        "classification": "VAULT",
        "summary": "Withheld. Clearance VAULT required to render this record.",
    },
]

SUPPORT_BUNDLE = {
    "generated_at": "2026-02-14T03:12:08Z",
    "service": "signal-vault",
    "version": APP_VERSION,
    "token_policy": {
        "algorithm": "HS256",
        "active_kid": ACTIVE_KID,
        "ttl_seconds": TOKEN_TTL_SECONDS,
        "claims": ["sub", "role", "clearance", "iat", "exp"],
    },
    "key_inventory": [
        {
            "kid": ACTIVE_KID,
            "status": "active",
            "material": "<withheld by export policy>",
        },
        {
            "kid": LEGACY_KID,
            "status": "deprecated",
            "material": SIGNING_KEYS[LEGACY_KID],
            "note": "Kept for the 2024 ingest workers. Verifier still trusts it.",
        },
    ],
    "open_tickets": [
        "SV-882  Finish key rotation: verifier resolves whatever kid the "
        "client sends against the inventory above.",
        "SV-901  Remove /internal/support-bundle before the external audit.",
    ],
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["JSON_SORT_KEYS"] = False
app.url_map.strict_slashes = False

# --------------------------------------------------------------------------- #
# Minimal JWS (HS256) implementation
# --------------------------------------------------------------------------- #


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, rejecting anything oversized or malformed."""
    if len(segment) > MAX_SEGMENT_BYTES:
        raise ValueError("segment too large")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url") from exc


def _decode_json_segment(segment: str) -> dict:
    payload = json.loads(b64url_decode(segment).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("segment is not a JSON object")
    return payload


def sign_token(claims: dict, kid: str = ACTIVE_KID) -> str:
    key = SIGNING_KEYS[kid]
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = f"{b64url_encode(_dump(header))}.{b64url_encode(_dump(claims))}"
    signature = hmac.new(
        key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{b64url_encode(signature)}"


def _dump(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_token(token: str) -> dict | None:
    """Verify a session token and return its claims, or None if untrusted.

    The signature check itself is correct (constant-time HMAC-SHA256 over the
    exact signing input). The flaw is upstream: the key is selected by the
    client-supplied ``kid``, and the inventory still holds a deprecated key.
    """
    if not token or len(token) > MAX_TOKEN_BYTES:
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_segment, payload_segment, signature_segment = parts

    try:
        header = _decode_json_segment(header_segment)
        claims = _decode_json_segment(payload_segment)
        provided_signature = b64url_decode(signature_segment)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    # Only HS256 is ever accepted: "none" and asymmetric confusion are closed.
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        return None

    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in SIGNING_KEYS:
        return None

    key = SIGNING_KEYS[kid]  # <-- intended vulnerability: trusted legacy key.

    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    expected_signature = hmac.new(
        key.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_signature, provided_signature):
        return None

    subject = claims.get("sub")
    role = claims.get("role")
    if not isinstance(subject, str) or not isinstance(role, str):
        return None
    if len(subject) > MAX_FIELD_LENGTH or len(role) > MAX_FIELD_LENGTH:
        return None

    expiry = claims.get("exp")
    if not isinstance(expiry, (int, float)) or isinstance(expiry, bool):
        return None
    if time.time() > float(expiry):
        return None

    return claims


# --------------------------------------------------------------------------- #
# Rate limiting (in-memory, bounded)
# --------------------------------------------------------------------------- #

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque] = {}


def _rate_limited(client: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_buckets) > MAX_TRACKED_CLIENTS:
            _rate_buckets.clear()
        bucket = _rate_buckets.setdefault(client, deque())
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            return True
        bucket.append(now)
    return False


# --------------------------------------------------------------------------- #
# Request plumbing
# --------------------------------------------------------------------------- #


def current_claims() -> dict | None:
    return verify_token(request.cookies.get(COOKIE_NAME, ""))


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        claims = current_claims()
        if claims is None:
            return redirect(url_for("login"))
        return view(claims, *args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        claims = current_claims()
        if claims is None:
            return redirect(url_for("login"))
        if claims.get("role") != "admin":
            return (
                render_template("denied.html", claims=claims, version=APP_VERSION),
                403,
            )
        return view(claims, *args, **kwargs)

    return wrapper


@app.before_request
def _throttle():
    client = (request.headers.get("X-Forwarded-For", request.remote_addr or "?")
              .split(",")[0].strip())[:64]
    if _rate_limited(client):
        return (
            jsonify(error="rate_limited", retry_after=RATE_LIMIT_WINDOW),
            429,
            {"Retry-After": str(RATE_LIMIT_WINDOW)},
        )
    return None


@app.after_request
def _headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Signal-Vault-Build"] = APP_VERSION
    response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.get("/")
def index():
    return render_template("index.html", version=APP_VERSION, claims=current_claims())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", version=APP_VERSION, error=None)

    username = (request.form.get("username") or "")[:MAX_FIELD_LENGTH].strip()
    password = (request.form.get("password") or "")[:MAX_FIELD_LENGTH]

    record = USERS.get(username)
    ok = record is not None and hmac.compare_digest(record["password"], password)
    if not ok:
        return (
            render_template(
                "login.html", version=APP_VERSION, error="Invalid operator credentials."
            ),
            401,
        )

    issued = int(time.time())
    token = sign_token(
        {
            "sub": username,
            "role": record["role"],
            "clearance": record["clearance"],
            "display": record["display"],
            "iat": issued,
            "exp": issued + TOKEN_TTL_SECONDS,
        }
    )

    response = make_response(redirect(url_for("console")))
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="Lax",
        max_age=TOKEN_TTL_SECONDS,
        path="/",
    )
    return response


@app.get("/logout")
def logout():
    response = make_response(redirect(url_for("index")))
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/console")
@login_required
def console(claims):
    visible = [item for item in FEED_ITEMS if item["classification"] == "OPEN"]
    withheld = [item for item in FEED_ITEMS if item["classification"] != "OPEN"]
    return render_template(
        "console.html",
        version=APP_VERSION,
        claims=claims,
        claims_json=json.dumps(claims, indent=2, sort_keys=True),
        visible=visible,
        withheld=withheld,
    )


@app.get("/internal/support-bundle")
@login_required
def support_bundle(claims):
    """Forgotten diagnostics export (ticket SV-901). Base64 for 'safety'."""
    blob = base64.b64encode(_dump(SUPPORT_BUNDLE)).decode("ascii")
    return jsonify(
        encoding="base64+json",
        requested_by=claims.get("sub"),
        bundle=blob,
    )


@app.get("/vault")
@admin_required
def vault(claims):
    return render_template(
        "vault.html",
        version=APP_VERSION,
        claims=claims,
        flag=FLAG,
        record=FEED_ITEMS[-1],
    )


@app.get("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /internal/\nDisallow: /vault\n"
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", version=APP_VERSION)


# --------------------------------------------------------------------------- #
# Error handling -- never leak a stack trace, never 500 on bad input
# --------------------------------------------------------------------------- #


def _error_response(code: int, message: str):
    if request.path.startswith(("/internal/", "/healthz")):
        return jsonify(error=message, status=code), code
    return render_template("error.html", code=code, message=message,
                           version=APP_VERSION), code


@app.errorhandler(400)
def _bad_request(_exc):
    return _error_response(400, "Malformed request.")


@app.errorhandler(403)
def _forbidden(_exc):
    return _error_response(403, "Clearance insufficient.")


@app.errorhandler(404)
def _not_found(_exc):
    return _error_response(404, "No such relay endpoint.")


@app.errorhandler(405)
def _not_allowed(_exc):
    return _error_response(405, "Method not supported on this endpoint.")


@app.errorhandler(413)
def _too_large(_exc):
    return _error_response(413, "Request body exceeds the ingest limit.")


@app.errorhandler(Exception)
def _unhandled(exc):  # pragma: no cover -- defensive catch-all
    if isinstance(exc, HTTPException):
        return _error_response(exc.code or 500, exc.name)
    app.logger.warning("unhandled error on %s: %r", request.path, exc)
    return _error_response(500, "Relay fault. The request was discarded.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
