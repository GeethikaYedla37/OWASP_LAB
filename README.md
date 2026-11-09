# Student Portal Security Lab

This is a minimal, deliberately insecure Flask application for an authorized local classroom demonstration. It includes a matching hardened mode so the same Burp Suite or OWASP ZAP requests can be replayed after each fix.

> **Local-only warning:** vulnerable mode is intentionally unsafe. It always binds to `127.0.0.1`; do not deploy it, expose it through a tunnel, or use real names/passwords/data.

## What is included

- Admin and Student login with generic accounts
- Student comment box
- Intentionally vulnerable and secure launch modes
- SQLite databases kept separate by mode
- SQL injection, stored XSS, brute force, session/logout, access-control, plaintext-password, and debug-error demonstrations
- Automated checks for the vulnerable result and its secure counterpart
- 24 ready-to-use input/output screenshots under `screenshots/`, including a genuine Burp Proxy before/after pair

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Admin | `admin1` | `admin123` |
| Student | `student1` | `student123` |

Vulnerable mode stores those values in plain text. Secure mode creates a separate database and stores password hashes.

## Install

```bash
cd flask-security-lab
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Flask 3.1.2 is already sufficient; no JavaScript build step is required.

## Run vulnerable mode

```bash
./run-vulnerable.sh --reset
```

Open <http://127.0.0.1:5000>. Debug mode is on, passwords are plain text, sessions have no server-side expiry, and logout deliberately leaves a captured cookie usable.

## Run secure mode

Use another terminal:

```bash
./run-secure.sh --reset
```

Open <http://127.0.0.1:5001>. The secure profile uses parameterized SQL, password hashing, escaped output plus CSP, login throttling, role checks, a 15-minute server-side session expiry, session revocation on logout, and generic error output.

The two modes use different cookie names and database files, so they can run together. For the cleanest recording, reset each mode first.

## Run the automated verification

```bash
python3 -m unittest discover -s tests -v
```

The checks confirm both halves of every demonstration: the deliberately vulnerable behavior occurs only in vulnerable mode, while the same input is blocked or rendered harmlessly in secure mode.

## Quick vulnerability matrix

| OWASP demonstration | Vulnerable mode | Secure mode |
|---|---|---|
| SQL injection | Concatenated login query; `admin1' -- ` bypasses the wrong password | Parameterized lookup + password hash check returns `401` |
| Stored XSS | Comments use unescaped rendering | Jinja escaping + CSP shows the payload as text |
| Brute force | Unlimited bad logins | Fifth failure returns `429` with `Retry-After` |
| Plaintext passwords | Password column contains the real demo password | Password column contains a Werkzeug hash |
| Session timeout | Database expiry is `NULL` | Server-side expiry is 15 minutes |
| Logout replay | Cookie and database session remain valid | Session row is deleted and cookie is cleared |
| Broken access control | Any signed-in user can request `/admin` | Student receives `403 Forbidden` |
| Debug/misconfiguration | Debug mode on; controlled page exposes traceback/config values | Debug off; generic `500` page and secure headers |

## Burp Suite setup

1. Start one mode and open Burp Suite.
2. In Burp's browser, visit the matching localhost URL.
3. In **Proxy → Intercept**, turn interception on.
4. Submit the login form and send the request to **Repeater**.
5. Change only the localhost request values described in [RECORDING_GUIDE.md](RECORDING_GUIDE.md).
6. Keep the target restricted to `127.0.0.1`.

Burp's default proxy listener is usually `127.0.0.1:8080`. Use Burp's own browser to avoid separate proxy configuration.

## OWASP ZAP setup

1. Start ZAP and use **Manual Explore**.
2. Enter `http://127.0.0.1:5000` for vulnerable mode or `http://127.0.0.1:5001` for secure mode.
3. Explore only this localhost target.
4. Use the Requester to replay the exact inputs from the recording guide.
5. Run a passive scan first. If you run an active scan, keep the target strictly limited to this lab.

Run Burp and ZAP one at a time if they both try to use port `8080`.

## Database evidence

After starting each mode, compare password storage:

```bash
sqlite3 data/lab-vulnerable.db \
  "SELECT username, role, password FROM users;"

sqlite3 data/lab-secure.db \
  "SELECT username, role, password FROM users;"
```

The Admin dashboard also presents the same difference visually for the recording.

## Resetting a take

Stop the selected server, then restart it with `--reset`. This removes only that mode's local database and recreates the two generic users and one starter comment.

## Project layout

```text
app.py                 Flask application and both security profiles
templates/             Login, Student, Admin, error, and message pages
static/                Local CSS and campus illustration
tests/test_lab.py       Automated vulnerable-versus-secure checks
RECORDING_GUIDE.md      Exact payloads, Burp/ZAP flow, and shot list
screenshots/            Browser evidence plus Burp request/response captures
```
