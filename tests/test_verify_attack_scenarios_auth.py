import json
import unittest
from unittest.mock import patch

from simulation.verify_attack_scenarios import _get_events, _login


class FakeResponse:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self._body


class VerifyAttackScenarioAuthenticationTests(unittest.TestCase):
    @patch("simulation.verify_attack_scenarios.urllib.request.urlopen")
    def test_login_posts_credentials_and_returns_token(self, urlopen):
        urlopen.return_value = FakeResponse(
            {"token": "test-token", "user": {"username": "analyst"}}
        )

        token, username = _login(
            "http://127.0.0.1:5000",
            "analyst",
            "test-password",
        )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:5000/login")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {"username": "analyst", "password": "test-password"},
        )
        self.assertEqual(token, "test-token")
        self.assertEqual(username, "analyst")

    @patch("simulation.verify_attack_scenarios.urllib.request.urlopen")
    def test_get_events_sends_bearer_token(self, urlopen):
        urlopen.return_value = FakeResponse({"events": [{"event_id": "event-1"}]})

        events = _get_events("http://127.0.0.1:5000", "test-token")

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "http://127.0.0.1:5000/api/events?limit=1000",
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(events, [{"event_id": "event-1"}])


if __name__ == "__main__":
    unittest.main()
