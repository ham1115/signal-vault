# Signal Vault — challenge briefing

## Public player description

> **Signal Vault** — Web Exploitation — Intermediate
>
> The Signal Vault relay console aggregates unattributed radio intercepts. Most
> records are open to analysts, but one is sealed behind a VAULT clearance that
> only the station lead holds.
>
> The team migrated their session tokens last spring. The migration is, by their
> own admission, not finished.
>
> An analyst account is published for the open house: `guest` / `guest`
>
> `http://<HOST>:8080/`
>
> Scope: this web host only. The laptop, the event network, the scoreboard and
> other players' sessions are out of scope. Denial of service is not a solution
> path and will not be scored.

**Flag format:** `CTF{...}`

## Lore (for the event programme)

Station HAVEN logged a 2.401 GHz burst from Relay Echo three weeks ago and
immediately reclassified the record VAULT. The duty analyst who filed it was
told the signal was "equipment noise" and that the matter was closed.

It was not closed. The console's own ticket queue shows a key rotation that
stalled halfway: the ingest workers from the 2024 build still sign with a
development key, so the verifier was told to accept whichever key a token asks
for. Nobody went back to narrow it down.

## Hints (release on a timer or on request)

1. **+15 min** — Your session token is not opaque. The console decodes it for
   you. Read the header, not just the claims.
2. **+30 min** — The token header names the key that signed it. Ask yourself
   what happens if you name a different one.
3. **+45 min** — Someone left a diagnostics export wired up during the
   migration. The console's HTML remembers where.

## Author notes

- **Difficulty rationale:** three linked steps, none individually hard. Decode a
  JWT and notice the `kid` header → find the leaked key inventory → re-sign with
  the deprecated key and a changed `role`. The signature check itself is
  correct, so the "strip the signature" and "`alg: none`" reflexes both fail,
  which is what lifts this out of beginner territory.
- **Rabbit holes closed on purpose:** `r.mendoza`'s password is a random 32-byte
  token (credential brute force is dead), the active signing key is random per
  boot (HMAC cracking is dead), there is no SQL and no filesystem read, and the
  login form reflects nothing (no SSTI or XSS).
- **Expected time:** 20–40 minutes for a player who has seen JWTs before.
