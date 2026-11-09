# Recording and Screenshot Guide

Use only this localhost lab. The payloads below are harmless visual sentinels chosen for repeatable screenshots.

## Before recording

1. Start vulnerable mode with `./run-vulnerable.sh --reset`.
2. Use `http://127.0.0.1:5000` in the browser/Burp/ZAP.
3. Keep secure mode at `http://127.0.0.1:5001` for the matching re-test.
4. Do not show the Werkzeug debugger PIN, your real filesystem path, or unrelated proxy history.
5. Mask the middle of captured cookie values in any manually recorded Burp screenshot.

## 1. Baseline login

Student:

```text
Username: student1
Password: student123
Account type: Student
```

Admin:

```text
Username: admin1
Password: admin123
Account type: Admin
```

Expected: each account reaches its matching dashboard.

## 2. SQL injection authentication bypass

Capture `POST /login` and change the form values to:

```text
username=admin1' -- 
password=definitely-wrong
role=admin
```

URL-encoded body:

```text
username=admin1%27+--+&password=definitely-wrong&role=admin
```

- Vulnerable result: `303` redirect to `/admin`, even with the wrong password.
- Secure result: `401 Invalid credentials` and no authenticated cookie.

Take one screenshot with the payload filled into the login form/Repeater and one with the resulting page.

## 3. Stored XSS

Log in as `student1` and submit this comment:

``Logout and captured-cookie replay

1. Log in as `student1`.
2. Capture the `portal_session_vulnerable` cookie from a request to `/student`.
3. Click **Log out**.
4. In Repeater, send `GET /student` with the original cookie.
`html
<svg onload="document.getElementById('xss-status').textContent='XSS_EXECUTED'"></svg>
```

- Vulnerable result: the comment is inserted as HTML and the visible line changes to `Script status: XSS_EXECUTED`.
- Secure result: the exact payload is displayed as normal text and the line remains `NOT_EXECUTED`.

This proof changes only text in the local page; it does not send data anywhere.

## 4. Brute force / missing rate limit

Send at least six login requests for `student1` with different wrong passwords.

- Vulnerable result: all attempts return `401`; there is no lockout.
- Secure result: the fifth failure and later attempts return `429` with a `Retry-After` header for 60 seconds.

Burp Community users can duplicate requests in Repeater. If using Intruder, keep concurrency low and the target limited to localhost.

## 5. 
- Vulnerable result: replay still returns `200` and the dashboard.
- Secure result with `portal_session_secure`: replay after logout redirects to `/login` because the server-side row was revoked.

## 6. Broken access control

1. Log in normally as `student1`.
2. Intercept or send `GET /admin` with the student cookie.

- Vulnerable result: `200` Admin dashboard, including the visible “Broken access control demonstrated” callout.
- Secure result: `403 Access denied`; no account table is returned.

## 7. Security misconfiguration / debug information

Request:

```http
GET /debug-error HTTP/1.1
Host: 127.0.0.1:5000
```

- Vulnerable result: controlled `500` page shows `DEBUG=True`, a sample internal database path, a training-only secret, and `DEMO_ERROR_TOKEN_42` traceback text.
- Secure result: generic `500` page without those details. Secure responses also include CSP, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.

The route intentionally uses controlled sample details so your real workstation path and debugger PIN do not appear in the supplied screenshots.

## 8. Plaintext password storage

Open the Admin dashboard or run the two SQLite commands from the README.

- Vulnerable result: `admin123` and `student123` are visible in the stored-value column.
- Secure result: the values begin with a password-hash method and do not reveal the original password.

## Supplied screenshot order

The `screenshots/vulnerable/` and `screenshots/secure/` directories contain numbered browser input/output evidence. `screenshots/burp/` contains the identical SQL-injection request and its vulnerable `303 /admin` versus secure `401` responses in Burp Proxy.

Recommended recording order:

1. Login page and normal Student dashboard
2. SQLi input → vulnerable Admin output → secure rejection → Burp request/response comparison
3. XSS input → vulnerable executed status → secure escaped output
4. Student `/admin` request → vulnerable Admin output → secure `403`
5. Logout/cookie replay result in each mode
6. Debug-detail output → generic secure error
7. Plaintext Admin table → secure hashed table
8. Mobile login page for responsive proof

Finish by running:

```bash
python3 -m unittest discover -s tests -v
```

Show the passing summary as the final verification step.
