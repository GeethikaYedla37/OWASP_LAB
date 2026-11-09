"""
WSGI entry point that serves BOTH modes from a single Render deployment.

Landing page at / lets you pick Vulnerable or Secure mode,
then routes to /vulnerable/... or /secure/... accordingly.
Each mode has its own SQLite DB and its own session cookie.

Run locally:
    gunicorn wsgi:app
    # then open http://localhost:8000/
"""
from flask import Flask, render_template_string
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from app import create_app

# One app instance per mode (databases auto-create on first request)
vuln_app = create_app("vulnerable")
sec_app = create_app("secure")

# Mode-selection landing page
landing = Flask(__name__)

LANDING_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Lab — Select Mode</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f5f7fa; color: #1f2937; display: flex; flex-direction: column; align-items: center; padding: 40px 20px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 32px; width: 100%; max-width: 640px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05); }
  h1 { margin-top: 0; font-size: 1.5rem; }
  p { margin: 8px 0 22px; color: #4b5563; }
  .mode { margin: 12px 0; padding: 18px; border-radius: 10px; text-decoration: none; display: block; font-weight: 600; font-size: 1.1rem; border: 2px solid transparent; }
  .mode:hover { filter: brightness(0.95); }
  .vulnerable { background: #fef2f2; color: #991b1b; border-color: #fca5a5; }
  .secure { background: #f0fdf4; color: #166534; border-color: #86efac; }
  .tag { font-weight: 400; font-size: 0.85rem; opacity: 0.85; display: block; margin-top: 6px; }
  .hint { margin-top: 24px; font-size: 0.9rem; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 16px; }
  .hint b { color: #111827; }
  code { background: #eef2f7; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="card">
    <h1>🔐 Security Lab — Choose Mode</h1>
    <p>Pick the profile you want to assess with Burp Suite.</p>

    <a class="mode vulnerable" href="/vulnerable/login">
      🔓 Vulnerable Mode
      <span class="tag">— SQLi, XSS, weak session, no lockout, debug traces</span>
    </a>

    <a class="mode secure" href="/secure/login">
      🔒 Secure Mode
      <span class="tag">— parameterized queries, escaped output, lockout, security headers</span>
    </a>

    <div class="hint">
      <b>Tip:</b> In Burp Suite, set the target to this Render URL and use
      <code>/vulnerable</code> or <code>/secure</code> as the path prefix.
    </div>
  </div>
</body>
</html>
"""

@landing.route("/")
def index():
    return render_template_string(LANDING_HTML)

# Mount each mode under its own URL prefix
app = DispatcherMiddleware(landing, {
    "/vulnerable": vuln_app,
    "/secure": sec_app,
})