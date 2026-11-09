"""
WSGI entry point for production deployment (e.g. Render).

Run locally:
    gunicorn wsgi:app

Render starts this automatically via the Procfile.
The LAB_MODE environment variable selects 'vulnerable' or 'secure'
(defaults to 'vulnerable' if not set).
"""
from app import create_app

app = create_app()