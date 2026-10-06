"""Authenticated Flask test client without using the real analyst database."""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator
from unittest import TestCase

from dashboard.app import create_dashboard_app
from dashboard.auth import create_user


TEST_PASSWORD = "A-long-test-password-123"


def make_authenticated_dashboard_client(test_case: TestCase):
    directory = TemporaryDirectory()
    test_case.addCleanup(directory.cleanup)
    db_path = Path(directory.name) / "analysts.db"
    create_user(db_path, "analyst@gmail.com", TEST_PASSWORD)
    client = create_dashboard_app(
        auth_path=db_path, session_secret="test-session-secret-at-least-32-characters"
    ).test_client()
    page = client.get("/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match is not None
    response = client.post(
        "/login",
        data={"email": "analyst@gmail.com", "password": TEST_PASSWORD, "csrf_token": match.group(1)},
    )
    assert response.status_code == 302
    return client


@contextmanager
def authenticated_dashboard_client() -> Iterator:
    class CleanupCase(TestCase):
        pass

    case = CleanupCase()
    try:
        yield make_authenticated_dashboard_client(case)
    finally:
        case.doCleanups()
