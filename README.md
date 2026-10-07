# Signal Vault — Web Exploitation CTF (intermediate)

> **New to Docker?** Follow [RUNNING.md](RUNNING.md) instead — a step-by-step
> guide for **macOS, Windows and Linux**, from installing Docker to
> resetting between rounds.

Self-contained Flask challenge for a LAN-hosted event. No internet, no CDNs, no
database engine, no writable state. Vulnerability class: **JWT manipulation**
(key-identifier confusion against a retained, leaked legacy signing key).

```
signal-vault/
├── app.py                 # the whole application
├── templates/             # 7 Jinja templates, CSS inlined in base.html
├── requirements.txt       # Flask + gunicorn, pinned
├── Dockerfile             # non-root, read-only-friendly
├── docker-compose.yml     # LAN bind, containment, resource caps
├── flag.txt               # default flag (replace before the event)
├── solve.py               # reference solver, stdlib only
└── tests/abuse_test.py    # 50-check guardrail suite
```

---

## 1. Setting the flag

Two options; the environment variable wins if both are present. Either way the
flag is read **once at boot into memory**, so deleting or editing the host file
mid-round cannot break a running container.

**Option A — environment variable (preferred).** Create `.env` next to
`docker-compose.yml`:

```
CTF_FLAG=CTF{your_real_flag_here}
```

**Option B — read-only file.** Put the flag in `./flag.txt`; compose mounts it
at `/flag.txt:ro`. Leave `CTF_FLAG` empty.

Other knobs (all optional):

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTF_FLAG` | *(unset)* | Flag string; falls back to `/flag.txt`. |
| `CTF_LEGACY_KEY` | `svc-dev-rotate-me` | The intended solution key. Change it to invalidate leaked writeups. |
| `CTF_MAIN_KEY` | *random per boot* | Leave unset. A fresh 64-char key each boot makes the active key uncrackable. |
| `CTF_RATE_LIMIT` | `240` | Requests per window per client IP. |
| `CTF_RATE_WINDOW` | `60` | Window in seconds. Raise the limit if your venue NATs all players behind one address. |

---

## 2. Event operations

### Build once, while you still have internet

```bash
cd signal-vault
docker compose build
```

Build is the only step that needs network access (PyPI). After this the
challenge runs fully offline.

**Fully offline laptop?** Build on a machine with internet, then move the image:

```bash
docker save signal-vault:1.0 | gzip > signal-vault-1.0.tar.gz   # on the build box
gunzip -c signal-vault-1.0.tar.gz | docker load                  # on the event laptop
docker compose up -d                                             # uses the loaded image
```

### Start

```bash
docker compose up -d
docker compose ps          # expect "healthy" within ~10 s
```

### Find your LAN address to publish to players

```bash
# macOS
ipconfig getifaddr en0
# Linux
hostname -I | awk '{print $1}'
```

Players use `http://<that-address>:8080/`. If port 8080 is taken, change the
host side of the mapping in `docker-compose.yml` (`"0.0.0.0:9000:8080"`) — leave
the container side at 8080.

### Clean restart between rounds

```bash
docker compose down && docker compose up -d
```

This is a genuine reset: the app holds *all* mutable state in process memory
(rate-limit buckets, the random active signing key), so a fresh container means
a fresh key and no residue from the previous round. Every outstanding token
issued in the previous round stops verifying under the active `kid`.

Faster, same effect for in-round hiccups:

```bash
docker compose restart signal-vault
```

### Watch it during the event

```bash
docker compose logs -f --tail=50     # access log, one line per request
docker stats signal-vault            # live CPU / memory against the caps
```

### Resource caps

Set in `docker-compose.yml`, mirrored across both the `deploy.resources` block
(Compose v2) and the top-level `cpus` / `mem_limit` keys (older binaries):

- **1.00 CPU**, **256 MB memory**, `memswap_limit` equal to the memory cap so a
  runaway container cannot start swapping the laptop to death.
- **128 PIDs**, so no fork bomb.
- Gunicorn: 2 workers × 4 threads, 20 s hard request timeout,
  `--max-requests 2000` with jitter so workers recycle and cannot leak.
- Logs capped at 2 × 5 MB, so a fuzzer cannot fill the disk.

Measured footprint at idle is well under 100 MB. A room of 40 players browsing
is comfortably inside one core.

---

## 3. Containment model

| Control | Setting | Stops |
| --- | --- | --- |
| Non-root | `USER 10001:10001`, no shell, no home | Writing anywhere outside tmpfs |
| Read-only root FS | `read_only: true` | Defacement, flag tampering, dropping webshells |
| Code permissions | `chmod a-w` on `/app` | Editing `app.py` or templates |
| tmpfs | `/tmp` and `/dev/shm`, `noexec,nosuid,nodev`, 8/16 MB | Dropping and executing a binary |
| Capabilities | `cap_drop: ALL`, `no-new-privileges` | Privilege escalation, raw sockets |
| No DB, no disk writes | all state in process memory | Cross-player tampering, persistence |
| Stateless sessions | JWT in an `HttpOnly` cookie | Touching another player's session — there is no server-side session store to poison |

The flag never touches the filesystem inside the container (env var path) or is
read once from a read-only mount. Even a hypothetical RCE would find a
read-only root, no capabilities, and a 256 MB cgroup.

---

## 4. Verification before you open the doors

```bash
python3 solve.py http://<lan-ip>:8080        # must print the flag
python3 tests/abuse_test.py http://<lan-ip>:8080   # must print "all guardrail checks passed"
```

Both are stdlib-only. The abuse suite runs 50 checks: 13 token-forgery attempts
that must be rejected, 11 malformed-token cases, 12 SSTI/SQLi/traversal/XSS
payloads through the login form, path and method abuse, an oversized body, and a
burst test. Any `5xx` is a failure.

Verified on this build: solver captures the flag, all 50 guardrail checks pass,
zero `5xx` responses in the access log.
