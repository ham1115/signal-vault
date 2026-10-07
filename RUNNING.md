# How to run Signal Vault

Written for someone who has never used Docker. Covers **macOS, Windows and
Linux**. Follow it top to bottom the first time; after that you only need
sections 4 and 7.

Where commands differ by platform, all three are shown. Run the one for the
machine that will host the challenge.

---

## 0. The two concepts, in plain terms

**Docker** packages the challenge — Python, Flask, the app, its exact versions —
into one bundle called an *image*. When you run that image you get a
*container*: an isolated mini-computer on your laptop. The app inside can only
see what you let it see, and deleting the container deletes everything it did.
That's why it's safe to hand to players: they are poking at the container, not
at your actual machine.

You will only ever type three Docker commands: `build` (make the image), `up`
(start a container), `down` (stop and delete it). These are **identical on all
three operating systems** — that is the entire point of Docker.

**The `.env` file** is a plain text file holding one `NAME=value` per line.
Docker reads it automatically and passes those values into the container as
*environment variables*. The app reads `CTF_FLAG` from there. It exists so the
real flag lives in exactly one file that is never committed to git — which is
why `.gitignore` lists it. Nothing magic: it's a two-line text file.

---

## 1. Install Docker (once)

### macOS

1. Download Docker Desktop: https://www.docker.com/products/docker-desktop/
   Pick **Apple Silicon** for M1/M2/M3/M4, **Intel chip** for older Macs.
   (Apple menu → About This Mac tells you which.)
2. Open the `.dmg`, drag Docker to Applications, launch it.
3. Accept the terms. You do **not** need a Docker account — skip the sign-in.
4. Wait for the whale icon in the menu bar to stop animating.

### Windows 10 / 11

Docker on Windows runs on **WSL2** (Windows Subsystem for Linux), a lightweight
Linux layer. Docker Desktop installs it for you, but it needs hardware
virtualisation switched on.

1. Open PowerShell **as Administrator** and run:
   ```powershell
   wsl --install
   ```
   Reboot when it asks. If it says WSL is already installed, run
   `wsl --update` instead.
2. Download Docker Desktop: https://www.docker.com/products/docker-desktop/
   (the Windows AMD64 build, unless you have an ARM Surface).
3. Run the installer, leaving **"Use WSL 2 instead of Hyper-V"** ticked.
4. Reboot, launch Docker Desktop, accept the terms, skip the sign-in.
5. Wait for the bottom-left status in Docker Desktop to go green / "Engine
   running".

If step 1 errors with something about virtualisation, it's disabled in your
firmware. Reboot into BIOS/UEFI and enable **Intel VT-x** or **AMD-V** (often
listed under CPU or Advanced settings). Docker cannot work without it.

Works on Windows Home as well as Pro — WSL2 removed that restriction.

### Linux (Ubuntu / Debian / Mint)

Don't install Docker Desktop on Linux; install the engine directly. It's far
lighter, which matters on modest hardware.

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

Then **log out and back in** (or reboot) so the group change takes effect.
Without it every Docker command needs `sudo`.

On Fedora/RHEL the same script works. On Arch: `sudo pacman -S docker
docker-compose` then `sudo systemctl enable --now docker`.

### Confirm it works (all platforms)

Open a terminal — **Terminal** on macOS, **PowerShell** or **Windows Terminal**
on Windows, your usual shell on Linux — and run:

```bash
docker --version
docker compose version
```

Both must print a version number.

- `command not found` / `not recognized` → Docker isn't installed, or on
  Windows/macOS the Desktop app isn't running yet.
- `Cannot connect to the Docker daemon` → the engine isn't started. Launch
  Docker Desktop, or on Linux: `sudo systemctl start docker`.
- `docker compose` unrecognised but `docker-compose` works → you have the old
  standalone version. Use `docker-compose` (with the hyphen) everywhere below.

---

## 2. Go to the project folder

**macOS / Linux**
```bash
cd ~/Documents/ctf/signal-vault
ls
```

**Windows (PowerShell)**
```powershell
cd ~\Documents\ctf\signal-vault
dir
```

Either way you should see `app.py`, `Dockerfile` and `docker-compose.yml`
listed. If you cloned the repo somewhere else, `cd` there instead.

---

## 3. Set your flag

Look at the current flag:

| | |
| --- | --- |
| macOS / Linux | `cat .env` |
| Windows | `type .env` |

```
CTF_FLAG=CTF{...whatever your flag is...}
```

To change it, open the file in a text editor:

| | |
| --- | --- |
| macOS | `open -e .env` |
| Windows | `notepad .env` |
| Linux | `nano .env` (Ctrl+O to save, Ctrl+X to quit) |

Edit the line, keeping the shape exactly — **no spaces around the `=`, no
quotes**:

```
CTF_FLAG=CTF{your_new_flag_here}
```

If you ever lose `.env`, recreate it:

| | |
| --- | --- |
| macOS / Linux | `echo 'CTF_FLAG=CTF{your_flag}' > .env` |
| Windows | `'CTF_FLAG=CTF{your_flag}' \| Out-File -Encoding utf8 .env` |

A flag change only takes effect on the next `down` + `up` (section 7) — the app
reads the flag once at startup.

**Windows note:** if Notepad saves the file and the app still reports no flag,
Notepad may have written a byte-order mark. Save as UTF-8 (not "UTF-8 with
BOM"), or use the `Out-File -Encoding utf8` command above.

---

## 4. Build and start

These are the same on every platform.

**Build** — turns the recipe into an image. Needs internet (downloads Python and
Flask). 1–3 minutes the first time, seconds afterwards.

```bash
docker compose build
```

**Start** — runs the container in the background.

```bash
docker compose up -d
```

`-d` means *detached*: it runs in the background and gives your terminal back.

**Check it came up healthy:**

```bash
docker compose ps
```

`STATUS` should read `Up ... (healthy)`. If it says `starting`, wait ten seconds
and run it again.

**Open it yourself:**

| | |
| --- | --- |
| macOS | `open http://localhost:8080` |
| Windows | `start http://localhost:8080` |
| Linux | `xdg-open http://localhost:8080` |

Or just type `localhost:8080` into your browser. Log in with `guest` / `guest`.

---

## 5. Let players reach it over the event Wi-Fi

Find your machine's address on the local network:

**macOS**
```bash
ipconfig getifaddr en0
```
Prints nothing? You're on Ethernet or a second adapter — try `en1`.

**Windows**
```powershell
ipconfig
```
Look under your active adapter (usually "Wireless LAN adapter Wi-Fi") for
**IPv4 Address**. Or, more directly:
```powershell
(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" }).IPAddress
```

**Linux**
```bash
hostname -I | awk '{print $1}'
```

You'll get something like `192.168.1.37`. Players use
**`http://192.168.1.37:8080`** — your number, not that one.

### Firewall

- **macOS** may ask whether to allow incoming connections the first time. Click
  **Allow**. If you clicked Deny: System Settings → Network → Firewall →
  Options.
- **Windows** will show a Windows Defender Firewall prompt. Tick **Private
  networks** and click **Allow access**. If you dismissed it, run PowerShell as
  Administrator:
  ```powershell
  New-NetFirewallRule -DisplayName "Signal Vault CTF" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow -Profile Private
  ```
  Also check Windows isn't treating the event Wi-Fi as a *Public* network —
  Settings → Network & Internet → Wi-Fi → your network → set to **Private**.
  Public blocks inbound connections.
- **Linux** with `ufw` active:
  ```bash
  sudo ufw allow 8080/tcp
  ```
  With `firewalld` (Fedora/RHEL):
  ```bash
  sudo firewall-cmd --add-port=8080/tcp
  ```

### Two more things that bite everyone

- **Your IP changes.** Reconnecting to the Wi-Fi can get you a new address.
  Re-run the command and re-announce it.
- **Client isolation.** Lots of venue and hotspot Wi-Fi blocks device-to-device
  traffic outright, and no amount of Docker or firewall work fixes it. **Test
  from a second device before the event.** If it's blocked, bring your own
  travel router or use a phone hotspot.

---

## 6. Verify the challenge actually works

Both scripts use only the Python standard library.

| | |
| --- | --- |
| macOS / Linux | `python3 solve.py http://localhost:8080` |
| Windows | `py -3 solve.py http://localhost:8080` |

The last line must print your flag. If it does, the challenge is solvable.

| | |
| --- | --- |
| macOS / Linux | `python3 tests/abuse_test.py http://localhost:8080` |
| Windows | `py -3 tests\abuse_test.py http://localhost:8080` |

Must end with `all guardrail checks passed` — 50 hostile payloads, none of which
should crash the app.

**Windows without Python?** It isn't installed by default. Get it from
https://www.python.org/downloads/ and tick **"Add python.exe to PATH"** during
install. Or skip it: the scripts are a nice-to-have, and you can verify by
solving the challenge manually in a browser.

Run both once more against your LAN address to confirm players can reach it, not
just you.

---

## 7. During and between rounds

Identical on all platforms.

**Clean reset** — your main command between rounds. Deletes the container and
starts a fresh one, wiping all state and generating a new internal signing key:

```bash
docker compose down && docker compose up -d
```

On Windows PowerShell, `&&` works in PowerShell 7+. On older PowerShell 5, run
the two commands on separate lines instead.

About five seconds. No rebuild needed unless you changed the code.

**Quick restart** if something's stuck but you don't need a full reset:

```bash
docker compose restart
```

**Watch requests live.** Ctrl+C stops watching — it does **not** stop the
challenge:

```bash
docker compose logs -f
```

**Check it isn't eating the laptop** (Ctrl+C to exit):

```bash
docker stats signal-vault
```

Memory should sit well under the 256 MB cap.

**Stop for the day:**

```bash
docker compose down
```

Nothing is lost — `up -d` brings it back.

---

## 8. Troubleshooting

| Symptom | Platform | Cause | Fix |
| --- | --- | --- | --- |
| `Cannot connect to the Docker daemon` | all | Engine not running | Launch Docker Desktop; Linux: `sudo systemctl start docker` |
| `permission denied ... docker.sock` | Linux | Not in the `docker` group | `sudo usermod -aG docker $USER`, then log out and back in |
| `docker compose` not recognised | all | Old standalone version | Use `docker-compose` with a hyphen |
| WSL / virtualisation errors on install | Windows | VT-x / AMD-V disabled | Enable it in BIOS/UEFI |
| `port is already allocated` | all | 8080 in use | Edit `docker-compose.yml`: `"0.0.0.0:9000:8080"`, then `down` + `up -d`. Players use `:9000` |
| Page shows `flag_was_not_configured` | all | `.env` missing or malformed | Check it reads `CTF_FLAG=CTF{...}`, no spaces or quotes, then `down` + `up -d` |
| Same, but `.env` looks right | Windows | Notepad added a BOM | Re-save as plain UTF-8, or use `Out-File -Encoding utf8` |
| Flag change didn't apply | all | Flag read at startup | `docker compose down && docker compose up -d` |
| `STATUS` stuck `starting` / `unhealthy` | all | App failed to boot | `docker compose logs` and read the error |
| Works locally, not from phones | macOS | Firewall | Section 5 |
| Works locally, not from phones | Windows | Network set to Public | Set the Wi-Fi to **Private**, section 5 |
| Works locally, not from phones | Linux | `ufw` / `firewalld` | `sudo ufw allow 8080/tcp`, section 5 |
| Works locally, not from phones | all | Wi-Fi client isolation | Not fixable on the host. Use your own router or hotspot |
| Players get `429 Too Many Requests` | all | Rate limit, or shared IP | Add `CTF_RATE_LIMIT=600` to `.env`, then `down` + `up -d` |
| Build fails downloading packages | all | No internet | Build needs internet once. See README's `docker save` / `docker load` route |
| Very slow build or file access | Windows | Project on the Windows filesystem | Optional: move the repo inside WSL (`\\wsl$\Ubuntu\home\you\`) for much faster disk I/O |

`docker compose logs` is always the first place to look — the app logs one line
per request and hides nothing.

---

## 9. Running without Docker (testing only)

Handy for a quick look while editing. **Do not use this at the event** — it
skips every containment control, so players would hit a plain Python process
with access to your real filesystem.

**macOS / Linux**
```bash
cd ~/Documents/ctf/signal-vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
CTF_FLAG='CTF{local_test}' python3 app.py
```

**Windows (PowerShell)**
```powershell
cd ~\Documents\ctf\signal-vault
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:CTF_FLAG='CTF{local_test}'; py -3 app.py
```

If PowerShell refuses to run the activate script, allow it for this session:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

Then open http://localhost:8080. Ctrl+C stops it; `deactivate` leaves the
virtual environment.

---

## Cheat sheet

Platform-independent, once you're in the project folder:

```bash
docker compose build                        # once, needs internet
docker compose up -d                        # start
docker compose ps                           # is it healthy?
docker compose down && docker compose up -d # reset between rounds
docker compose logs -f                      # watch traffic
docker compose down                         # stop
```

The only platform-specific bits:

| Task | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Open the app | `open http://localhost:8080` | `start http://localhost:8080` | `xdg-open http://localhost:8080` |
| Find your LAN IP | `ipconfig getifaddr en0` | `ipconfig` → IPv4 Address | `hostname -I` |
| Run the solver | `python3 solve.py URL` | `py -3 solve.py URL` | `python3 solve.py URL` |
| Edit the flag | `open -e .env` | `notepad .env` | `nano .env` |
