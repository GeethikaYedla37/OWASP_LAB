from __future__ import annotations

import argparse
import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask,
    Response,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
VALID_MODES = {"vulnerable", "secure"}
DEFAULT_SESSION_SECONDS = 15 * 60
LOGIN_LIMIT = 5
LOCKOUT_SECONDS = 60


def create_app(
    mode: str | None = None,
    database_path: str | Path | None = None,
    *,
    testing: bool = False,
    session_seconds: int | None = None,
    reset_database: bool = False,
) -> Flask:
    """Application factory used by both the server and the automated checks."""

    selected_mode = (mode or os.environ.get("LAB_MODE", "vulnerable")).lower()
    if selected_mode not in VALID_MODES:
        raise ValueError("LAB_MODE must be 'vulnerable' or 'secure'")

    is_vulnerable = selected_mode == "vulnerable"
    default_db = BASE_DIR / "data" / f"lab-{selected_mode}.db"
    db_path = Path(database_path or default_db).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if reset_database and db_path.exists():
        db_path.unlink()

    app = Flask(__name__)
    app.config.update(
        LAB_MODE=selected_mode,
        IS_VULNERABLE=is_vulnerable,
        COOKIE_NAME=f"portal_session_{selected_mode}",
        DATABASE=str(db_path),
        TESTING=testing,
        DEBUG=is_vulnerable,
        SESSION_SECONDS=(
            session_seconds
            if session_seconds is not None
            else int(os.environ.get("SECURE_SESSION_SECONDS", DEFAULT_SESSION_SECONDS))
        ),
        LOGIN_LIMIT=LOGIN_LIMIT,
        LOCKOUT_SECONDS=LOCKOUT_SECONDS,
    )

    # This deliberately weak, hard-coded key exists only in vulnerable mode.
    # Secure mode uses fresh process-local entropy. The app uses server-side
    # session IDs, so neither value is treated as a user credential.
    app.secret_key = (
        "training-only-debug-secret"
        if is_vulnerable
        else secrets.token_hex(32)
    )

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            connection = sqlite3.connect(app.config["DATABASE"])
            connection.row_factory = sqlite3.Row
            g.db = connection
        return g.db

    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def initialize_database() -> None:
        database = sqlite3.connect(app.config["DATABASE"])
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'student'))
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                attempt_key TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                locked_until INTEGER NOT NULL
            );
            """
        )

        user_count = database.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            seed_users = [
                ("admin1", "admin123", "admin"),
                ("student1", "student123", "student"),
            ]
            for username, password, role in seed_users:
                stored_password = (
                    password
                    if is_vulnerable
                    else generate_password_hash(password)
                )
                database.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, stored_password, role),
                )

            student_id = database.execute(
                "SELECT id FROM users WHERE username = ?", ("student1",)
            ).fetchone()[0]
            database.execute(
                "INSERT INTO comments (user_id, body, created_at) VALUES (?, ?, ?)",
                (student_id, "Welcome to the class portal.", int(time.time())),
            )

        database.commit()
        database.close()

    initialize_database()

    def login_required(view: Callable[..., Response | str]) -> Callable[..., Response | str]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Response | str:
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.before_request
    def load_current_user() -> None:
        g.user = None
        g.session_id = None
        sid = request.cookies.get(app.config["COOKIE_NAME"])
        if not sid:
            return

        row = get_db().execute(
            """
            SELECT sessions.sid, sessions.expires_at,
                   users.id, users.username, users.role
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.sid = ?
            """,
            (sid,),
        ).fetchone()
        if row is None:
            return

        expires_at = row["expires_at"]
        if not is_vulnerable and (expires_at is None or expires_at <= int(time.time())):
            get_db().execute("DELETE FROM sessions WHERE sid = ?", (sid,))
            get_db().commit()
            return

        g.session_id = sid
        g.user = {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }

    @app.context_processor
    def shared_template_values() -> dict[str, Any]:
        return {
            "current_user": g.get("user"),
            "is_vulnerable": is_vulnerable,
            "lab_mode": selected_mode,
        }

    def attempt_key(username: str) -> str:
        return f"{request.remote_addr or 'local'}:{username.lower()}"

    def active_lockout(username: str) -> int:
        row = get_db().execute(
            "SELECT locked_until FROM login_attempts WHERE attempt_key = ?",
            (attempt_key(username),),
        ).fetchone()
        if row is None:
            return 0
        remaining = row["locked_until"] - int(time.time())
        return max(0, remaining)

    def register_failed_login(username: str) -> tuple[int, int]:
        key = attempt_key(username)
        row = get_db().execute(
            "SELECT attempts, locked_until FROM login_attempts WHERE attempt_key = ?",
            (key,),
        ).fetchone()
        attempts = (row["attempts"] if row else 0) + 1
        locked_until = row["locked_until"] if row else 0
        if attempts >= app.config["LOGIN_LIMIT"]:
            locked_until = int(time.time()) + app.config["LOCKOUT_SECONDS"]
        get_db().execute(
            """
            INSERT INTO login_attempts (attempt_key, attempts, locked_until)
            VALUES (?, ?, ?)
            ON CONFLICT(attempt_key) DO UPDATE SET
                attempts = excluded.attempts,
                locked_until = excluded.locked_until
            """,
            (key, attempts, locked_until),
        )
        get_db().commit()
        return attempts, max(0, locked_until - int(time.time()))

    def clear_failed_logins(username: str) -> None:
        get_db().execute(
            "DELETE FROM login_attempts WHERE attempt_key = ?",
            (attempt_key(username),),
        )
        get_db().commit()

    def create_server_session(user_id: int) -> tuple[str, int | None]:
        sid = secrets.token_urlsafe(32)
        now = int(time.time())
        expires_at = None if is_vulnerable else now + app.config["SESSION_SECONDS"]
        get_db().execute(
            "INSERT INTO sessions (sid, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (sid, user_id, now, expires_at),
        )
        get_db().commit()
        return sid, expires_at

    @app.get("/")
    def index() -> Response:
        if g.user is None:
            return redirect(url_for("login"))
        destination = "admin" if g.user["role"] == "admin" else "student"
        return redirect(url_for(destination))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> tuple[str, int] | Response:
        if request.method == "GET" and g.user is not None:
            destination = "admin" if g.user["role"] == "admin" else "student"
            return redirect(url_for(destination))

        error: str | None = None
        status_code = 200
        entered_username = request.args.get("username", "")
        entered_role = request.args.get("role", "student")

        if request.method == "POST":
            entered_username = request.form.get("username", "")
            password = request.form.get("password", "")
            entered_role = request.form.get("role", "student")

            if entered_role not in {"student", "admin"}:
                entered_role = "student"

            if not is_vulnerable:
                remaining = active_lockout(entered_username)
                if remaining:
                    response = make_response(
                        render_template(
                            "login.html",
                            error=f"Too many attempts. Try again in {remaining} seconds.",
                            entered_username=entered_username,
                            entered_role=entered_role,
                        ),
                        429,
                    )
                    response.headers["Retry-After"] = str(remaining)
                    return response

            user = None
            if is_vulnerable:
                # INTENTIONALLY VULNERABLE: untrusted values are concatenated
                # directly into a SQL statement for local SQLi practice.
                query = (
                    "SELECT id, username, password, role FROM users "
                    f"WHERE username = '{entered_username}' "
                    f"AND password = '{password}' "
                    f"AND role = '{entered_role}' LIMIT 1"
                )
                try:
                    user = get_db().execute(query).fetchone()
                except sqlite3.Error as database_error:
                    error = f"Database error: {database_error}"
                    status_code = 500
            else:
                candidate = get_db().execute(
                    "SELECT id, username, password, role FROM users "
                    "WHERE username = ? AND role = ? LIMIT 1",
                    (entered_username, entered_role),
                ).fetchone()
                if candidate and check_password_hash(candidate["password"], password):
                    user = candidate

            if user is not None:
                if not is_vulnerable:
                    clear_failed_logins(entered_username)
                sid, _expires_at = create_server_session(user["id"])
                destination = "admin" if user["role"] == "admin" else "student"
                response = make_response(redirect(url_for(destination), code=303))
                response.set_cookie(
                    app.config["COOKIE_NAME"],
                    sid,
                    max_age=None if is_vulnerable else app.config["SESSION_SECONDS"],
                    httponly=not is_vulnerable,
                    secure=False,
                    samesite=None if is_vulnerable else "Lax",
                )
                return response

            if error is None:
                error = "Invalid credentials."
                status_code = 401
                if not is_vulnerable:
                    attempts, lock_seconds = register_failed_login(entered_username)
                    if lock_seconds:
                        error = f"Too many attempts. Try again in {lock_seconds} seconds."
                        status_code = 429

        response = make_response(
            render_template(
                "login.html",
                error=error,
                entered_username=entered_username,
                entered_role=entered_role,
            ),
            status_code,
        )
        if status_code == 429:
            response.headers["Retry-After"] = str(app.config["LOCKOUT_SECONDS"])
        return response

    @app.get("/student")
    @login_required
    def student() -> str:
        comments = get_db().execute(
            """
            SELECT comments.id, comments.body, comments.created_at,
                   users.username
            FROM comments
            JOIN users ON users.id = comments.user_id
            ORDER BY comments.id DESC
            """
        ).fetchall()
        return render_template("student.html", comments=comments)

    @app.post("/comments")
    @login_required
    def add_comment() -> Response | tuple[str, int]:
        body = request.form.get("comment", "").strip()
        if not body:
            return render_template(
                "message.html",
                title="Comment required",
                message="Enter a comment before submitting.",
                status_label="Bad request",
            ), 400
        if not is_vulnerable and len(body) > 1000:
            return render_template(
                "message.html",
                title="Comment too long",
                message="Comments are limited to 1,000 characters.",
                status_label="Bad request",
            ), 400

        get_db().execute(
            "INSERT INTO comments (user_id, body, created_at) VALUES (?, ?, ?)",
            (g.user["id"], body, int(time.time())),
        )
        get_db().commit()
        return redirect(url_for("student"), code=303)

    @app.get("/admin")
    @login_required
    def admin() -> tuple[str, int] | str:
        if not is_vulnerable and g.user["role"] != "admin":
            return render_template(
                "message.html",
                title="Access denied",
                message="This page is available only to administrators.",
                status_label="403 Forbidden",
            ), 403

        users = get_db().execute(
            "SELECT id, username, password, role FROM users ORDER BY id"
        ).fetchall()
        return render_template("admin.html", users=users)

    @app.route("/logout", methods=["GET", "POST"])
    def logout() -> Response:
        if not is_vulnerable and g.session_id:
            get_db().execute("DELETE FROM sessions WHERE sid = ?", (g.session_id,))
            get_db().commit()

        response = make_response(redirect(url_for("login"), code=303))
        if not is_vulnerable:
            response.delete_cookie(app.config["COOKIE_NAME"])
        # Vulnerable mode deliberately leaves both the cookie and server-side
        # record valid, so a captured cookie can still be replayed.
        return response

    @app.get("/debug-error")
    def debug_error() -> tuple[str, int]:
        if is_vulnerable:
            demo_traceback = """Traceback (most recent call last):
  File \"/srv/student-portal/app.py\", line 314, in debug_error
    raise RuntimeError(\"DEMO_ERROR_TOKEN_42\")
RuntimeError: DEMO_ERROR_TOKEN_42"""
            return render_template(
                "debug_error.html",
                demo_traceback=demo_traceback,
                database_label="/srv/student-portal/data/lab-vulnerable.db",
                secret_label="training-only-debug-secret",
            ), 500

        return render_template(
            "message.html",
            title="Something went wrong",
            message="The request could not be completed. Please try again later.",
            status_label="500 Error",
        ), 500

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": selected_mode}

    @app.after_request
    def apply_response_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        if not is_vulnerable:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self'; script-src 'self'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local Flask security teaching lab")
    parser.add_argument(
        "--mode",
        choices=sorted(VALID_MODES),
        default=os.environ.get("LAB_MODE", "vulnerable"),
        help="Launch the intentionally vulnerable or hardened profile.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Listening port (defaults to 5000 vulnerable / 5001 secure).",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset only the selected mode's local SQLite database before launch.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_args()
    listening_port = arguments.port or (5000 if arguments.mode == "vulnerable" else 5001)
    application = create_app(arguments.mode, reset_database=arguments.reset)
    application.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", listening_port)),
        debug=arguments.mode == "vulnerable",
        use_reloader=False,
    )
