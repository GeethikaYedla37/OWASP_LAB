from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from werkzeug.security import check_password_hash


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from app import create_app  # noqa: E402


class SecurityLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        temp_path = Path(self.temp_directory.name)
        self.vulnerable_db = temp_path / "vulnerable.db"
        self.secure_db = temp_path / "secure.db"
        self.vulnerable_app = create_app(
            "vulnerable", self.vulnerable_db, testing=True
        )
        self.secure_app = create_app("secure", self.secure_db, testing=True)

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    @staticmethod
    def login(client, username: str, password: str, role: str):
        return client.post(
            "/login",
            data={"username": username, "password": password, "role": role},
            follow_redirects=False,
        )

    def session_id(self, app, client) -> str:
        cookie = client.get_cookie(app.config["COOKIE_NAME"])
        self.assertIsNotNone(cookie)
        return cookie.value

    def test_normal_student_and_admin_logins(self) -> None:
        for app in (self.vulnerable_app, self.secure_app):
            student_client = app.test_client()
            admin_client = app.test_client()
            student_response = self.login(
                student_client, "student1", "student123", "student"
            )
            admin_response = self.login(
                admin_client, "admin1", "admin123", "admin"
            )
            self.assertEqual(student_response.status_code, 303)
            self.assertTrue(student_response.headers["Location"].endswith("/student"))
            self.assertEqual(admin_response.status_code, 303)
            self.assertTrue(admin_response.headers["Location"].endswith("/admin"))

    def test_sql_injection_bypasses_only_vulnerable_login(self) -> None:
        payload = "admin1' -- "

        vulnerable_client = self.vulnerable_app.test_client()
        vulnerable_response = self.login(
            vulnerable_client, payload, "definitely-wrong", "admin"
        )
        self.assertEqual(vulnerable_response.status_code, 303)
        self.assertTrue(vulnerable_response.headers["Location"].endswith("/admin"))
        admin_page = vulnerable_client.get("/admin")
        self.assertIn(b'data-testid="admin-dashboard"', admin_page.data)

        secure_client = self.secure_app.test_client()
        secure_response = self.login(
            secure_client, payload, "definitely-wrong", "admin"
        )
        self.assertEqual(secure_response.status_code, 401)
        self.assertIn(b"Invalid credentials", secure_response.data)
        self.assertIsNone(
            secure_client.get_cookie(self.secure_app.config["COOKIE_NAME"])
        )

    def test_password_storage_plaintext_vs_hash(self) -> None:
        with closing(sqlite3.connect(self.vulnerable_db)) as database:
            vulnerable_password = database.execute(
                "SELECT password FROM users WHERE username = ?", ("student1",)
            ).fetchone()[0]
        with closing(sqlite3.connect(self.secure_db)) as database:
            secure_password = database.execute(
                "SELECT password FROM users WHERE username = ?", ("student1",)
            ).fetchone()[0]

        self.assertEqual(vulnerable_password, "student123")
        self.assertNotEqual(secure_password, "student123")
        self.assertTrue(check_password_hash(secure_password, "student123"))

    def test_stored_xss_is_raw_only_in_vulnerable_mode(self) -> None:
        payload = (
            '<svg onload="document.getElementById(\'xss-status\')'
            ".textContent='XSS_EXECUTED'\"></svg>"
        )

        vulnerable_client = self.vulnerable_app.test_client()
        self.login(vulnerable_client, "student1", "student123", "student")
        vulnerable_client.post("/comments", data={"comment": payload})
        vulnerable_page = vulnerable_client.get("/student")
        self.assertIn(b"<svg onload=", vulnerable_page.data)

        secure_client = self.secure_app.test_client()
        self.login(secure_client, "student1", "student123", "student")
        secure_client.post("/comments", data={"comment": payload})
        secure_page = secure_client.get("/student")
        self.assertIn(b"&lt;svg onload=", secure_page.data)
        self.assertNotIn(b"<svg onload=", secure_page.data)

    def test_student_can_reach_admin_only_in_vulnerable_mode(self) -> None:
        vulnerable_client = self.vulnerable_app.test_client()
        self.login(vulnerable_client, "student1", "student123", "student")
        vulnerable_admin = vulnerable_client.get("/admin")
        self.assertEqual(vulnerable_admin.status_code, 200)
        self.assertIn(b"Broken access control demonstrated", vulnerable_admin.data)

        secure_client = self.secure_app.test_client()
        self.login(secure_client, "student1", "student123", "student")
        secure_admin = secure_client.get("/admin")
        self.assertEqual(secure_admin.status_code, 403)
        self.assertNotIn(b'data-testid="admin-dashboard"', secure_admin.data)

    def test_captured_cookie_replay_after_logout(self) -> None:
        vulnerable_client = self.vulnerable_app.test_client()
        self.login(vulnerable_client, "student1", "student123", "student")
        vulnerable_sid = self.session_id(self.vulnerable_app, vulnerable_client)
        vulnerable_client.post("/logout")
        vulnerable_replay = self.vulnerable_app.test_client()
        vulnerable_replay.set_cookie(
            self.vulnerable_app.config["COOKIE_NAME"], vulnerable_sid
        )
        self.assertEqual(vulnerable_replay.get("/student").status_code, 200)

        secure_client = self.secure_app.test_client()
        self.login(secure_client, "student1", "student123", "student")
        secure_sid = self.session_id(self.secure_app, secure_client)
        secure_client.post("/logout")
        secure_replay = self.secure_app.test_client()
        secure_replay.set_cookie(self.secure_app.config["COOKIE_NAME"], secure_sid)
        secure_result = secure_replay.get("/student")
        self.assertEqual(secure_result.status_code, 302)
        self.assertTrue(secure_result.headers["Location"].endswith("/login"))

    def test_brute_force_lockout_exists_only_in_secure_mode(self) -> None:
        vulnerable_client = self.vulnerable_app.test_client()
        vulnerable_statuses = [
            self.login(vulnerable_client, "student1", f"wrong-{index}", "student").status_code
            for index in range(6)
        ]
        self.assertEqual(vulnerable_statuses, [401, 401, 401, 401, 401, 401])

        secure_client = self.secure_app.test_client()
        secure_statuses = [
            self.login(secure_client, "student1", f"wrong-{index}", "student").status_code
            for index in range(5)
        ]
        self.assertEqual(secure_statuses, [401, 401, 401, 401, 429])
        blocked_correct_login = self.login(
            secure_client, "student1", "student123", "student"
        )
        self.assertEqual(blocked_correct_login.status_code, 429)
        self.assertIn("Retry-After", blocked_correct_login.headers)

    def test_secure_session_expiry_is_server_side(self) -> None:
        vulnerable_client = self.vulnerable_app.test_client()
        self.login(vulnerable_client, "student1", "student123", "student")
        vulnerable_sid = self.session_id(self.vulnerable_app, vulnerable_client)
        with closing(sqlite3.connect(self.vulnerable_db)) as database:
            vulnerable_expiry = database.execute(
                "SELECT expires_at FROM sessions WHERE sid = ?", (vulnerable_sid,)
            ).fetchone()[0]
        self.assertIsNone(vulnerable_expiry)

        secure_client = self.secure_app.test_client()
        self.login(secure_client, "student1", "student123", "student")
        secure_sid = self.session_id(self.secure_app, secure_client)
        with closing(sqlite3.connect(self.secure_db)) as database:
            database.execute(
                "UPDATE sessions SET expires_at = 0 WHERE sid = ?", (secure_sid,)
            )
            database.commit()
        expired_response = secure_client.get("/student")
        self.assertEqual(expired_response.status_code, 302)
        self.assertTrue(expired_response.headers["Location"].endswith("/login"))

    def test_debug_details_are_hidden_in_secure_mode(self) -> None:
        vulnerable_error = self.vulnerable_app.test_client().get("/debug-error")
        secure_error = self.secure_app.test_client().get("/debug-error")

        self.assertEqual(vulnerable_error.status_code, 500)
        self.assertIn(b"DEMO_ERROR_TOKEN_42", vulnerable_error.data)
        self.assertIn(b"Traceback", vulnerable_error.data)
        self.assertIn(b"training-only-debug-secret", vulnerable_error.data)

        self.assertEqual(secure_error.status_code, 500)
        self.assertIn(b"Something went wrong", secure_error.data)
        self.assertNotIn(b"DEMO_ERROR_TOKEN_42", secure_error.data)
        self.assertNotIn(b"Traceback", secure_error.data)

    def test_secure_headers_are_present(self) -> None:
        vulnerable_response = self.vulnerable_app.test_client().get("/login")
        secure_response = self.secure_app.test_client().get("/login")
        self.assertNotIn("Content-Security-Policy", vulnerable_response.headers)
        self.assertIn("Content-Security-Policy", secure_response.headers)
        self.assertEqual(secure_response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            secure_response.headers["X-Content-Type-Options"], "nosniff"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
