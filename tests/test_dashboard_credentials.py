"""Dashboard analyst authentication and authorization regression tests."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from unittest.mock import MagicMock

from dashboard import app as dashboard_module
from dashboard.auth import (
    MAX_LOGIN_FAILURES,
    approve_user,
    authenticate,
    begin_signup,
    complete_signup,
    create_user,
    initialize_auth_store,
    promote_admin,
    remove_user,
    reset_password,
    set_user_active,
    validate_password,
    verify_signup,
)
from dashboard.email_delivery import send_signup_code
from dashboard.mail_config import load_mail_config, normalize_gmail_address


PASSWORD = "Test-analyst-password-123"
EMAIL = "analyst@gmail.com"


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


@unittest.skipUnless(dashboard_module._FLASK_OK, "Flask not installed")
class DashboardCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_path = Path(self.directory.name) / "dashboard_users.db"
        create_user(self.db_path, EMAIL, PASSWORD)
        self.app = dashboard_module.create_dashboard_app(
            auth_path=self.db_path,
            session_secret="a-test-only-signing-key-longer-than-32-characters",
        )
        self.client = self.app.test_client()

    def configure_mail(self) -> Path:
        path = Path(self.directory.name) / "dashboard_mail.json"
        path.write_text(json.dumps({
            "sender_gmail": "sender@gmail.com",
            "gmail_app_password": "abcdefghijklmnop",
        }), encoding="utf-8")
        override = patch.dict(os.environ, {
            "DASHBOARD_MAIL_CONFIG": str(path),
            "DASHBOARD_SENDER_GMAIL": "",
            "DASHBOARD_GMAIL_APP_PASSWORD": "",
        })
        override.start()
        self.addCleanup(override.stop)
        return path

    def sign_in(self, client=None, *, password=PASSWORD):
        client = client or self.client
        page = client.get("/login")
        token = csrf_from(page.get_data(as_text=True))
        return client.post(
            "/login",
            data={"email": EMAIL, "password": password, "csrf_token": token},
        )

    def test_accounts_are_private_salted_hashes(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as db:
            row = db.execute("SELECT email, password_hash FROM dashboard_accounts").fetchone()
        self.assertEqual(row[0], EMAIL)
        self.assertNotIn(PASSWORD, row[1])
        self.assertTrue(row[1].startswith("pbkdf2:sha256:600000$"))
        self.assertNotEqual(self.db_path, Path("website/backend/data/honeypot.db"))

    def test_short_internal_dashboard_token_is_rejected(self) -> None:
        with patch.dict(os.environ, {"DASHBOARD_INTERNAL_TOKEN": "too-short"}):
            with self.assertRaisesRegex(RuntimeError, "at least 32 characters"):
                dashboard_module._dashboard_internal_token()

    def test_ips_proxy_uses_signed_in_identity_not_spoofed_headers(self) -> None:
        self.assertEqual(self.sign_in().status_code, 302)
        with self.client.session_transaction() as session:
            expected_id = session["analyst_user_id"]
            token = session["csrf_token"]
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"executed":true}'
        response.status = 201
        response.headers = {"Content-Type": "application/json"}
        with patch.object(dashboard_module, "_dashboard_internal_token", return_value="test-internal-token"), patch.object(dashboard_module.urllib.request, "urlopen", return_value=response) as send:
            reply = self.client.post("/api/ips/actions", json={"action_type": "rate_limit", "recommendation_id": 1}, headers={
                "X-CSRF-Token": token, "X-Dashboard-Analyst-Id": "999", "X-Dashboard-Analyst-Email": "spoof@gmail.com",
            })
        self.assertEqual(reply.status_code, 201)
        headers = {key.lower(): value for key, value in send.call_args.args[0].header_items()}
        self.assertEqual(headers["x-dashboard-analyst-id"], str(expected_id))
        self.assertEqual(headers["x-dashboard-analyst-email"], EMAIL)
        self.assertEqual(headers["x-dashboard-internal-token"], "test-internal-token")

    def test_anonymous_page_api_and_event_stream_are_protected(self) -> None:
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIn("Sign up with Gmail", self.client.get("/").get_data(as_text=True))
        for route in (
            "/api/monitor", "/api/honeypot", "/api/credentials", "/api/ids",
            "/api/agents", "/api/xai/alerts", "/api/report", "/api/report/download",
            "/api/analyst-feedback", "/api/ips/actions", "/stream",
        ):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 401)
        self.assertEqual(self.client.post("/api/xai/report").status_code, 401)

    def test_login_needs_csrf_and_gives_generic_failure(self) -> None:
        self.assertEqual(
            self.client.post("/login", data={"email": EMAIL, "password": PASSWORD}).status_code,
            403,
        )
        stale_page = self.client.post("/login", data={"email": EMAIL, "password": PASSWORD})
        self.assertIn("Sign-in page expired", stale_page.get_data(as_text=True))
        self.assertNotIn("Invalid CSRF token", stale_page.get_data(as_text=True))
        failed = self.sign_in(password="incorrect-password")
        self.assertEqual(failed.status_code, 401)
        self.assertIn("Invalid Gmail or password", failed.get_data(as_text=True))
        self.assertEqual(self.sign_in(password=PASSWORD + "x" * 1024).status_code, 401)
        signed_in = self.sign_in()
        self.assertEqual(signed_in.status_code, 302)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Sign out", dashboard.get_data(as_text=True))
        self.assertIn('data-toggle-password="password"', self.client.get("/login").get_data(as_text=True))
        cookie = signed_in.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_actions_need_csrf_and_logout_revokes_sessions(self) -> None:
        self.assertEqual(self.sign_in().status_code, 302)
        other = self.app.test_client()
        self.assertEqual(self.sign_in(other).status_code, 302)
        self.assertEqual(self.client.post("/api/xai/report").status_code, 403)
        self.assertEqual(self.client.post("/logout").status_code, 403)
        token = csrf_from(self.client.get("/").get_data(as_text=True))
        self.assertEqual(
            self.client.post("/logout", data={"csrf_token": token}).status_code, 302
        )
        self.assertEqual(self.client.get("/api/monitor").status_code, 401)
        self.assertEqual(other.get("/api/monitor").status_code, 401)

    def test_reset_and_disable_revoke_sessions(self) -> None:
        self.assertEqual(self.sign_in().status_code, 302)
        self.assertTrue(reset_password(self.db_path, EMAIL, "New-password-12345"))
        self.assertEqual(self.client.get("/api/monitor").status_code, 401)
        self.assertEqual(self.sign_in(password=PASSWORD).status_code, 401)
        self.assertEqual(self.sign_in(password="New-password-12345").status_code, 302)
        self.assertTrue(set_user_active(self.db_path, EMAIL, False))
        self.assertEqual(self.client.get("/api/monitor").status_code, 401)

    def test_failed_logins_are_rate_limited(self) -> None:
        for _ in range(MAX_LOGIN_FAILURES):
            user, limited, pending = authenticate(self.db_path, EMAIL, "bad-password", "127.0.0.1")
            self.assertIsNone(user)
            self.assertFalse(limited)
            self.assertFalse(pending)
        user, limited, pending = authenticate(self.db_path, EMAIL, PASSWORD, "127.0.0.1")
        self.assertIsNone(user)
        self.assertTrue(limited)
        self.assertFalse(pending)
        self.assertTrue(reset_password(self.db_path, EMAIL, PASSWORD))
        user, limited, pending = authenticate(self.db_path, EMAIL, PASSWORD, "127.0.0.1")
        self.assertIsNotNone(user)
        self.assertFalse(limited)
        self.assertFalse(pending)

    def test_https_cookie_option(self) -> None:
        with patch.dict(os.environ, {"DASHBOARD_COOKIE_SECURE": "1"}):
            app = dashboard_module.create_dashboard_app(
                auth_path=self.db_path, session_secret="another-test-signing-key-longer-than-32-chars"
            )
        response = app.test_client().get("/login")
        self.assertIn("Secure", response.headers["Set-Cookie"])

    def test_gmail_signup_otp_then_email_password_login(self) -> None:
        new_email = "newanalyst@gmail.com"
        new_password = "SafePass123!' OR 1=1 --"
        self.configure_mail()
        visitor = self.app.test_client()
        page = visitor.get("/").get_data(as_text=True)
        self.assertIn("Sign up with Gmail", page)
        self.assertNotIn('name="username"', page)
        signup_page = visitor.get("/signup").get_data(as_text=True)
        self.assertIn("Send OTP", signup_page)
        self.assertNotIn('name="password"', signup_page)
        self.assertEqual(visitor.get("/set-password").headers["Location"], "/signup")
        token = csrf_from(signup_page)
        with patch("dashboard.app.send_signup_code") as send:
            response = visitor.post("/signup", data={
                "email": new_email, "csrf_token": token,
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/verify-signup")
            send.assert_called_once()
            code = send.call_args.args[1]
            with closing(sqlite3.connect(self.db_path)) as db:
                challenge = db.execute(
                    "SELECT otp_digest FROM dashboard_email_challenges WHERE email = ?",
                    (new_email,),
                ).fetchone()
                self.assertEqual(db.execute(
                    "SELECT count(*) FROM dashboard_accounts WHERE email = ?", (new_email,)
                ).fetchone()[0], 0)
            self.assertNotIn(code, challenge[0])
            self.assertEqual(visitor.get("/api/monitor").status_code, 401)
            self.assertIn("Resend OTP", visitor.get("/verify-signup").get_data(as_text=True))
            self.assertEqual(visitor.post("/verify-signup", data={
                "otp": "999999" if code != "999999" else "888888", "csrf_token": token,
            }).status_code, 400)
            verified = visitor.post("/verify-signup", data={
                "otp": code, "csrf_token": token,
            })
            self.assertEqual(verified.status_code, 302)
            self.assertEqual(verified.headers["Location"], "/set-password")
            self.assertFalse(verify_signup(self.db_path, new_email, code, self.app.config["SECRET_KEY"]))
        password_page = visitor.get("/set-password").get_data(as_text=True)
        self.assertIn("Uppercase letter", password_page)
        self.assertIn("Re-enter password", password_page)
        self.assertIn('data-toggle-password="password"', password_page)
        self.assertIn('data-toggle-password="confirm_password"', password_page)
        self.assertEqual(visitor.post("/set-password", data={
            "password": "lowercase123!", "confirm_password": "lowercase123!",
            "csrf_token": token,
        }).status_code, 400)
        self.assertEqual(visitor.post("/set-password", data={
            "password": new_password, "confirm_password": "Different123!",
            "csrf_token": token,
        }).status_code, 400)
        self.assertEqual(visitor.get("/api/monitor").status_code, 401)
        created = visitor.post("/set-password", data={
            "password": new_password, "confirm_password": new_password,
            "csrf_token": token,
        })
        self.assertEqual(created.status_code, 302)
        self.assertEqual(created.headers["Location"], "/login?registered=pending")
        self.assertEqual(visitor.get("/set-password").status_code, 302)
        login_token = csrf_from(visitor.get("/login").get_data(as_text=True))
        pending_login = visitor.post("/login", data={
            "email": new_email, "password": new_password, "csrf_token": login_token,
        })
        self.assertEqual(pending_login.status_code, 401)
        self.assertIn("Approval pending", pending_login.get_data(as_text=True))
        self.assertIn('role="alertdialog"', pending_login.get_data(as_text=True))
        self.assertNotIn("Invalid CSRF token", pending_login.get_data(as_text=True))
        self.assertEqual(visitor.get("/api/monitor").status_code, 401)
        self.assertEqual(visitor.get("/admin/users").status_code, 302)
        with closing(sqlite3.connect(self.db_path)) as db:
            pending_id = db.execute(
                "SELECT id FROM dashboard_accounts WHERE email = ?", (new_email,)
            ).fetchone()[0]
        self.assertEqual(self.sign_in().status_code, 302)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        ordinary_token = csrf_from(self.client.get("/").get_data(as_text=True))
        self.assertEqual(self.client.post(
            f"/admin/users/{pending_id}/approve", data={"csrf_token": ordinary_token}
        ).status_code, 403)
        self.assertTrue(promote_admin(self.db_path, EMAIL))
        self.assertEqual(self.client.get("/admin/users").status_code, 302)
        self.assertEqual(self.sign_in().status_code, 302)
        admin_page = self.client.get("/admin/users")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn(new_email, admin_page.get_data(as_text=True))
        admin_token = csrf_from(admin_page.get_data(as_text=True))
        self.assertEqual(self.client.post(
            f"/admin/users/{pending_id}/approve"
        ).status_code, 403)
        self.assertEqual(self.client.post(
            f"/admin/users/{pending_id}/approve", data={"csrf_token": admin_token}
        ).status_code, 302)
        self.assertEqual(self.client.post(
            f"/admin/users/{pending_id}/approve", data={"csrf_token": admin_token}
        ).status_code, 404)
        self.assertEqual(visitor.post("/login", data={
            "email": new_email, "password": new_password, "csrf_token": login_token,
        }).status_code, 302)
        self.assertIn(new_email, visitor.get("/").get_data(as_text=True))
        self.assertNotIn("Manage users", visitor.get("/").get_data(as_text=True))
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM dashboard_accounts").fetchone()[0], 2)
            approval = db.execute(
                "SELECT approval_status, approved_by_id FROM dashboard_accounts WHERE id = ?",
                (pending_id,),
            ).fetchone()
            admin_id = db.execute(
                "SELECT id FROM dashboard_accounts WHERE email = ?", (EMAIL,)
            ).fetchone()[0]
            self.assertEqual(approval, ("approved", admin_id))

    def test_any_gmail_can_request_code_when_mail_is_configured(self) -> None:
        self.configure_mail()
        visitor = self.app.test_client()
        token = csrf_from(visitor.get("/signup").get_data(as_text=True))
        payload = {
            "email": "unknown@gmail.com", "csrf_token": token,
        }
        with patch("dashboard.app.send_signup_code") as send:
            self.assertEqual(visitor.post("/signup", data=payload).status_code, 302)
            send.assert_called_once()
        with patch.dict(os.environ, {"DASHBOARD_MAIL_CONFIG": str(Path(self.directory.name) / "missing.json")}):
            self.assertEqual(visitor.post("/signup", data=payload).status_code, 503)

    def test_verified_sender_gmail_bootstraps_first_admin(self) -> None:
        self.configure_mail()
        visitor = self.app.test_client()
        token = csrf_from(visitor.get("/signup").get_data(as_text=True))
        with patch("dashboard.app.send_signup_code") as send:
            self.assertEqual(visitor.post("/signup", data={
                "email": "sender@gmail.com", "csrf_token": token,
            }).status_code, 302)
        code = send.call_args.args[1]
        self.assertEqual(visitor.post("/verify-signup", data={
            "otp": code, "csrf_token": token,
        }).headers["Location"], "/set-password")
        self.assertEqual(visitor.post("/set-password", data={
            "password": PASSWORD, "confirm_password": PASSWORD, "csrf_token": token,
        }).headers["Location"], "/login?registered=approved")
        login_token = csrf_from(visitor.get("/login").get_data(as_text=True))
        self.assertEqual(visitor.post("/login", data={
            "email": "sender@gmail.com", "password": PASSWORD, "csrf_token": login_token,
        }).status_code, 302)
        self.assertIn("Manage users", visitor.get("/").get_data(as_text=True))
        self.assertEqual(visitor.get("/admin/users").status_code, 200)

    def test_admin_and_subadmin_user_management_boundaries(self) -> None:
        create_user(self.db_path, "sub@gmail.com", PASSWORD)
        create_user(self.db_path, "member@gmail.com", PASSWORD)
        create_user(self.db_path, "peer@gmail.com", PASSWORD)
        self.assertEqual(complete_signup(self.db_path, "waiting@gmail.com", PASSWORD), "pending")
        self.assertTrue(promote_admin(self.db_path, EMAIL))
        with closing(sqlite3.connect(self.db_path)) as db:
            ids = dict(db.execute("SELECT email, id FROM dashboard_accounts").fetchall())
            stored_hash = db.execute(
                "SELECT password_hash FROM dashboard_accounts WHERE email = ?", (EMAIL,)
            ).fetchone()[0]

        self.assertEqual(self.sign_in().status_code, 302)
        admin_page = self.client.get("/admin/users").get_data(as_text=True)
        admin_token = csrf_from(admin_page)
        for email in (EMAIL, "sub@gmail.com", "member@gmail.com", "waiting@gmail.com"):
            self.assertIn(email, admin_page)
        self.assertIn("Pending approval", admin_page)
        self.assertIn("Make subadmin", admin_page)
        self.assertNotIn(stored_hash, admin_page)
        self.assertEqual(self.client.post(
            f"/admin/users/{ids[EMAIL]}/remove", data={"csrf_token": admin_token}
        ).status_code, 403)
        self.assertEqual(self.client.post(
            f"/admin/users/{ids['sub@gmail.com']}/subadmin",
            data={"csrf_token": admin_token, "action": "grant"},
        ).status_code, 302)
        self.assertEqual(self.client.post(
            f"/admin/users/{ids['peer@gmail.com']}/subadmin",
            data={"csrf_token": admin_token, "action": "grant"},
        ).status_code, 302)

        def login_as(email: str):
            client = self.app.test_client()
            token = csrf_from(client.get("/login").get_data(as_text=True))
            response = client.post("/login", data={
                "email": email, "password": PASSWORD, "csrf_token": token,
            })
            self.assertEqual(response.status_code, 302)
            return client

        sub_client = login_as("sub@gmail.com")
        member_client = login_as("member@gmail.com")
        sub_page = sub_client.get("/admin/users").get_data(as_text=True)
        sub_token = csrf_from(sub_page)
        self.assertIn("Manage dashboard users", sub_page)
        self.assertNotIn("Make subadmin", sub_page)
        self.assertEqual(sub_client.post(
            f"/admin/users/{ids['waiting@gmail.com']}/approve",
            data={"csrf_token": sub_token},
        ).status_code, 302)
        self.assertEqual(sub_client.post(
            f"/admin/users/{ids['member@gmail.com']}/subadmin",
            data={"csrf_token": sub_token, "action": "grant"},
        ).status_code, 403)
        for protected_id in (ids[EMAIL], ids["sub@gmail.com"], ids["peer@gmail.com"]):
            self.assertEqual(sub_client.post(
                f"/admin/users/{protected_id}/remove", data={"csrf_token": sub_token},
            ).status_code, 403)
        self.assertEqual(sub_client.post(
            f"/admin/users/{ids['member@gmail.com']}/remove",
            data={"csrf_token": sub_token},
        ).status_code, 302)
        self.assertEqual(member_client.get("/api/monitor").status_code, 401)
        self.assertEqual(self.client.post(
            f"/admin/users/{ids['sub@gmail.com']}/remove",
            data={"csrf_token": admin_token},
        ).status_code, 302)
        self.assertEqual(sub_client.get("/api/monitor").status_code, 401)
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM dashboard_accounts WHERE email = ?", ("member@gmail.com",)
            ).fetchone())
            self.assertEqual(db.execute(
                "SELECT approval_status FROM dashboard_accounts WHERE email = ?",
                ("waiting@gmail.com",),
            ).fetchone()[0], "approved")

    def test_revoking_subadmin_invalidates_its_session(self) -> None:
        create_user(self.db_path, "sub@gmail.com", PASSWORD)
        self.assertTrue(promote_admin(self.db_path, EMAIL))
        with closing(sqlite3.connect(self.db_path)) as db:
            sub_id = db.execute(
                "SELECT id FROM dashboard_accounts WHERE email = ?", ("sub@gmail.com",)
            ).fetchone()[0]
        self.assertEqual(self.sign_in().status_code, 302)
        admin_token = csrf_from(self.client.get("/admin/users").get_data(as_text=True))
        self.assertEqual(self.client.post(
            f"/admin/users/{sub_id}/subadmin",
            data={"csrf_token": admin_token, "action": "grant"},
        ).status_code, 302)
        sub_client = self.app.test_client()
        sub_token = csrf_from(sub_client.get("/login").get_data(as_text=True))
        self.assertEqual(sub_client.post("/login", data={
            "email": "sub@gmail.com", "password": PASSWORD, "csrf_token": sub_token,
        }).status_code, 302)
        self.assertEqual(sub_client.get("/admin/users").status_code, 200)
        self.assertEqual(self.client.post(
            f"/admin/users/{sub_id}/subadmin",
            data={"csrf_token": admin_token, "action": "revoke"},
        ).status_code, 302)
        self.assertEqual(sub_client.get("/api/monitor").status_code, 401)
        sub_token = csrf_from(sub_client.get("/login").get_data(as_text=True))
        self.assertEqual(sub_client.post("/login", data={
            "email": "sub@gmail.com", "password": PASSWORD, "csrf_token": sub_token,
        }).status_code, 302)
        self.assertEqual(sub_client.get("/admin/users").status_code, 403)

    def test_deleted_account_id_is_not_reused_by_later_accounts(self) -> None:
        create_user(self.db_path, "removed@gmail.com", PASSWORD)
        self.assertTrue(promote_admin(self.db_path, EMAIL))
        with closing(sqlite3.connect(self.db_path)) as db:
            ids = dict(db.execute("SELECT email, id FROM dashboard_accounts").fetchall())
        old_client = self.app.test_client()
        token = csrf_from(old_client.get("/login").get_data(as_text=True))
        self.assertEqual(old_client.post("/login", data={
            "email": "removed@gmail.com", "password": PASSWORD, "csrf_token": token,
        }).status_code, 302)
        self.assertTrue(remove_user(self.db_path, ids[EMAIL], ids["removed@gmail.com"]))
        create_user(self.db_path, "replacement@gmail.com", PASSWORD)
        with closing(sqlite3.connect(self.db_path)) as db:
            replacement_id = db.execute(
                "SELECT id FROM dashboard_accounts WHERE email = ?", ("replacement@gmail.com",)
            ).fetchone()[0]
        self.assertGreater(replacement_id, ids["removed@gmail.com"])
        # Do not clear the old cookie before creating the replacement: it must
        # fail even when the replacement has the same initial auth_version.
        self.assertEqual(old_client.get("/api/monitor").status_code, 401)
        self.assertTrue(remove_user(self.db_path, ids[EMAIL], replacement_id))
        initialize_auth_store(self.db_path)
        self.assertEqual(complete_signup(self.db_path, "signup@gmail.com", PASSWORD), "pending")
        with closing(sqlite3.connect(self.db_path)) as db:
            signup_id = db.execute(
                "SELECT id FROM dashboard_accounts WHERE email = ?", ("signup@gmail.com",)
            ).fetchone()[0]
        self.assertGreater(signup_id, replacement_id)
        self.assertTrue(approve_user(self.db_path, ids[EMAIL], signup_id))

    def test_existing_account_table_migrates_without_losing_users(self) -> None:
        old_db = Path(self.directory.name) / "old-users.db"
        with closing(sqlite3.connect(old_db)) as db:
            db.execute("""
                CREATE TABLE dashboard_accounts (
                    id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, auth_version INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1, verified_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            db.execute("INSERT INTO dashboard_accounts "
                       "(email, password_hash, verified_at, created_at) VALUES (?, ?, 1, 1)",
                       ("old@gmail.com", "test-hash"))
            db.commit()
        initialize_auth_store(old_db)
        with closing(sqlite3.connect(old_db)) as db:
            row = db.execute(
                "SELECT approval_status, is_admin, is_subadmin FROM dashboard_accounts WHERE email = ?",
                ("old@gmail.com",),
            ).fetchone()
        self.assertEqual(row, ("approved", 0, 0))

    def test_failed_email_delivery_cancels_code(self) -> None:
        new_email = "newanalyst@gmail.com"
        self.configure_mail()
        visitor = self.app.test_client()
        token = csrf_from(visitor.get("/signup").get_data(as_text=True))
        with patch("dashboard.app.send_signup_code", side_effect=OSError("mail offline")):
            response = visitor.post("/signup", data={
                "email": new_email, "csrf_token": token,
            })
        self.assertEqual(response.status_code, 502)
        with closing(sqlite3.connect(self.db_path)) as db:
            pending = db.execute(
                "SELECT count(*) FROM dashboard_email_challenges WHERE email = ?", (new_email,)
            ).fetchone()[0]
        self.assertEqual(pending, 0)

    def test_signup_code_is_limited_and_expires(self) -> None:
        secret = self.app.config["SECRET_KEY"]
        self.configure_mail()
        with patch("dashboard.auth.time.time", return_value=1_000):
            email, code = begin_signup(self.db_path, "otp@gmail.com", secret)
            with self.assertRaisesRegex(ValueError, "wait one minute"):
                begin_signup(self.db_path, email, secret)
            wrong = "000000" if code != "000000" else "111111"
            for _ in range(5):
                self.assertFalse(verify_signup(self.db_path, email, wrong, secret))
            self.assertFalse(verify_signup(self.db_path, email, code, secret))
        with patch("dashboard.auth.time.time", return_value=1_700):
            self.assertFalse(verify_signup(self.db_path, email, code, secret))

    def test_gmail_aliases_share_one_identity_and_challenge(self) -> None:
        secret = self.app.config["SECRET_KEY"]
        self.assertEqual(
            normalize_gmail_address(" First.Last+test@GMAIL.COM "),
            "firstlast@gmail.com",
        )
        with patch("dashboard.auth.time.time", return_value=1_000):
            email, _ = begin_signup(
                self.db_path, "first.last+one@gmail.com", secret, "192.0.2.10"
            )
            self.assertEqual(email, "firstlast@gmail.com")
            with self.assertRaisesRegex(ValueError, "wait one minute"):
                begin_signup(
                    self.db_path, "f.i.r.s.t.l.a.s.t+two@gmail.com", secret, "192.0.2.11"
                )

    def test_signup_codes_are_rate_limited_by_source_ip(self) -> None:
        secret = self.app.config["SECRET_KEY"]
        with (
            patch("dashboard.auth.time.time", return_value=1_000),
            patch("dashboard.auth.OTP_IP_MAX_SENDS_PER_HOUR", 2),
        ):
            begin_signup(self.db_path, "ipone@gmail.com", secret, "192.0.2.20")
            begin_signup(self.db_path, "iptwo@gmail.com", secret, "192.0.2.20")
            with self.assertRaisesRegex(ValueError, "Too many verification codes"):
                begin_signup(self.db_path, "ipthree@gmail.com", secret, "192.0.2.20")
            begin_signup(self.db_path, "ipthree@gmail.com", secret, "192.0.2.21")

    def test_legacy_dotted_account_is_canonicalized(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute(
                "UPDATE dashboard_accounts SET email = ? WHERE email = ?",
                ("ana.lyst+old@gmail.com", EMAIL),
            )
            db.commit()
        initialize_auth_store(self.db_path)
        with closing(sqlite3.connect(self.db_path)) as db:
            stored = db.execute("SELECT email FROM dashboard_accounts").fetchone()[0]
        self.assertEqual(stored, EMAIL)

    def test_resend_otp_replaces_previous_code(self) -> None:
        email = "resend@gmail.com"
        self.configure_mail()
        visitor = self.app.test_client()
        token = csrf_from(visitor.get("/signup").get_data(as_text=True))
        with patch("dashboard.app.send_signup_code") as send:
            self.assertEqual(visitor.post("/signup", data={
                "email": email, "csrf_token": token,
            }).status_code, 302)
            old_code = send.call_args.args[1]
            self.assertEqual(visitor.post("/resend-otp", data={
                "csrf_token": token,
            }).status_code, 429)
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute(
                    "UPDATE dashboard_email_challenges SET last_sent_at = last_sent_at - 61, "
                    "first_sent_at = first_sent_at - 61 WHERE email = ?", (email,)
                )
                db.commit()
            response = visitor.post("/resend-otp", data={"csrf_token": token})
            self.assertEqual(response.status_code, 200)
            self.assertIn("previous code is no longer valid", response.get_data(as_text=True))
            new_code = send.call_args.args[1]
            self.assertNotEqual(new_code, old_code)
            self.assertEqual(visitor.post("/verify-signup", data={
                "otp": old_code, "csrf_token": token,
            }).status_code, 400)
            self.assertEqual(visitor.post("/verify-signup", data={
                "otp": new_code, "csrf_token": token,
            }).headers["Location"], "/set-password")

    def test_password_composition_rules(self) -> None:
        for weak in ("lowercase123!", "UPPERCASE123!", "NoNumbers!!", "NoSymbols123", "Aa1!"):
            with self.subTest(weak=weak), self.assertRaises(ValueError):
                validate_password(weak)
        self.assertEqual(validate_password(PASSWORD), PASSWORD)

    def test_gmail_delivery_uses_tls_and_sender_app_password(self) -> None:
        self.configure_mail()
        with patch("dashboard.email_delivery.smtplib.SMTP") as smtp:
            send_signup_code("newanalyst@gmail.com", "012345")
        smtp.assert_called_once_with("smtp.gmail.com", 587, timeout=10)
        connection = smtp.return_value.__enter__.return_value
        connection.starttls.assert_called_once()
        connection.login.assert_called_once_with("sender@gmail.com", "abcdefghijklmnop")
        message = connection.send_message.call_args.args[0]
        self.assertEqual(message["To"], "newanalyst@gmail.com")
        self.assertIn("012345", message.get_content())

    def test_mail_secret_is_validated_and_redacted(self) -> None:
        path = self.configure_mail()
        config = load_mail_config()
        self.assertIsNotNone(config)
        self.assertNotIn("abcdefghijklmnop", repr(config))
        path.write_text(json.dumps({
            "sender_gmail": "sender@gmail.com",
            "gmail_app_password": "too-short",
        }), encoding="utf-8")
        self.assertIsNone(load_mail_config())

    def test_mail_environment_override_avoids_secret_file(self) -> None:
        with patch.dict(os.environ, {
            "DASHBOARD_SENDER_GMAIL": "sen.der+smtp@gmail.com",
            "DASHBOARD_GMAIL_APP_PASSWORD": "ponmlkjihgfedcba",
            "DASHBOARD_MAIL_CONFIG": str(Path(self.directory.name) / "missing.json"),
        }):
            config = load_mail_config()
        self.assertIsNotNone(config)
        self.assertEqual(config.sender_gmail, "sender@gmail.com")
        self.assertEqual(config.gmail_app_password, "ponmlkjihgfedcba")


if __name__ == "__main__":
    unittest.main()
