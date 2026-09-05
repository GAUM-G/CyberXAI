from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class PublicPortalFrontendTests(unittest.TestCase):
    def test_react_routes_are_attacker_portal_only(self) -> None:
        app = read("website/frontend/src/App.jsx")

        self.assertIn('path="/"', app)
        self.assertNotIn('path="/signup"', app)
        self.assertNotIn('path="/dashboard"', app)
        self.assertNotIn("ProtectedRoute", app)
        self.assertNotIn("hp_token", app)

    def test_navigation_does_not_expose_analyst_features(self) -> None:
        shell = read("website/frontend/src/components/PortalShell.jsx")

        for marker in (
            "Northstar Dynamics",
            "Company",
            "Resources",
            "Employee Access",
        ):
            self.assertIn(marker, shell)

        self.assertNotIn("Security Dashboard", shell)
        self.assertNotIn("IDS Details", shell)
        self.assertNotIn("Create Account", shell)

    def test_portal_uses_only_decoy_interaction_endpoints(self) -> None:
        home = read("website/frontend/src/pages/HomePage.jsx")

        self.assertIn('apiRequest("/api/decoy/login"', home)
        self.assertIn("/api/decoy/search?q=", home)
        self.assertIn("/files/", home)
        self.assertNotIn('apiRequest("/login"', home)
        self.assertNotIn("/api/ids-results", home)
        self.assertNotIn("/api/ips", home)
        self.assertNotIn("localStorage", home)

    def test_exposure_panel_renders_data_as_react_text(self) -> None:
        component = read("website/frontend/src/components/ExposurePanel.jsx")

        for marker in (
            "exposure.exposed_items",
            "exposure.columns",
            "exposure.rows",
            "Legacy response console",
            "Clear output",
        ):
            self.assertIn(marker, component)

        self.assertNotIn("dangerouslySetInnerHTML", component)
        self.assertNotIn("innerHTML", component)

    def test_public_api_helper_never_sends_an_analyst_token(self) -> None:
        api = read("website/frontend/src/api.js")

        self.assertNotIn("hp_token", api)
        self.assertNotIn("Authorization", api)
        self.assertIn("/frontend/log", api)

    def test_portal_styles_cover_data_exposure_and_mobile_layouts(self) -> None:
        styles = read("website/frontend/src/styles.css")

        for selector in (
            ".public-portal",
            ".portal-grid",
            ".files-card",
            ".exposure-panel",
            ".exposure-table-wrap",
            "@media (max-width: 760px)",
        ):
            self.assertIn(selector, styles)


if __name__ == "__main__":
    unittest.main()
