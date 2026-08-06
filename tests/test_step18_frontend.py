from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "website" / "frontend"


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def sha256(relative_path: str) -> str:
    return hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest().upper()


class Step18FrontendTests(unittest.TestCase):
    def test_untouched_frontend_files_match_step18_baseline(self) -> None:
        expected = {
            "website/frontend/index.html": "6D1DDB715D99B84CE819DE75BB39BAA34D405A8E892A9C25342C536CC45E6EF7",
            "website/frontend/package.json": "7D064065BEC3998D64231B257F78F41AA52316BB798FE2FF0164EE09A236FEAC",
            "website/frontend/package-lock.json": "406A7A8FF53103E118DACFE7CDC61ADF8F03971C0E636A332D5672552ED8AE40",
            "website/frontend/src/api.js": "B527CB3BACCAB84E91E4C3B32EAB3DFEA4A09AF0E92767FC0FAC66B7AF8B6897",
            "website/frontend/src/App.jsx": "9667E2E2FC37EFD82AFEA379A36A7977B05A752008BB662E780A8C68CBD84143",
            "website/frontend/src/main.jsx": "B109869C3077F287DA962A730890C41BD130CD3B40A6EA2C7D15B952B61CAAEE",
            "website/frontend/src/pages/HomePage.jsx": "94561D9ED743842E81A2BC63A9D00E908857C4191EF2C1D0F853F67DD7B165D0",
            "website/frontend/src/pages/SignUpPage.jsx": "9E04AEF740FADB7EC603E9A6605001DF98FFE27DF5E7D8F8CEDC42AF64F29647",
            "website/frontend/vite.config.js": "DDC6D4FB9EB728AC2530E726582431A4D6A3B6D1BE035E142EA59776EF8A0DC6",
        }
        for relative_path, expected_hash in expected.items():
            with self.subTest(relative_path=relative_path):
                self.assertEqual(sha256(relative_path), expected_hash)

    def test_existing_routes_and_auth_storage_are_preserved(self) -> None:
        app = read("website/frontend/src/App.jsx")
        for route in ('path="/"', 'path="/signup"', 'path="/dashboard"'):
            self.assertIn(route, app)
        self.assertIn('localStorage.getItem("hp_token")', app)

    def test_navigation_is_added_without_removing_portal_heading(self) -> None:
        shell = read("website/frontend/src/components/PortalShell.jsx")
        self.assertIn('className="portal-nav"', shell)
        self.assertIn("Employee Portal", shell)
        self.assertIn("Security Dashboard", shell)
        self.assertIn("IDS Details", shell)
        self.assertIn("<h1>{title}</h1>", shell)
        self.assertIn("<p>{subtitle}</p>", shell)

    def test_existing_dashboard_and_xai_features_remain(self) -> None:
        dashboard = read("website/frontend/src/pages/DashboardPage.jsx")
        for protected_text in (
            "Security Panel",
            "Alerts Today",
            "Suspicious Logins",
            "Active Decoys",
            "XAI Alerts",
            "Refresh Alerts",
            "Generate XAI Report",
            "http://localhost:5678/webhook/xai-honeypot",
        ):
            self.assertIn(protected_text, dashboard)
        self.assertIn("<IDSInsights />", dashboard)

    def test_ids_details_use_final_results_and_sanitized_explanation(self) -> None:
        component = read("website/frontend/src/components/IDSInsights.jsx")
        self.assertIn('apiRequest("/api/ids-results?limit=100")', component)
        self.assertIn('apiRequest("/api/ids-results/stats")', component)
        self.assertIn("xai?.human_reason?.summary", component)
        for identifier in (
            'id="ids-insights"',
            'id="ids-search"',
            'id="ids-service-filter"',
            'id="ids-threat-filter"',
            'id="ids-prediction-filter"',
            'aria-labelledby="ids-dialog-title"',
        ):
            self.assertIn(identifier, component)
        self.assertNotIn("username", component.lower())
        self.assertNotIn("password", component.lower())

    def test_responsive_styles_cover_navigation_tables_and_details(self) -> None:
        styles = read("website/frontend/src/styles.css")
        for selector in (
            ".portal-nav",
            ".ids-summary",
            ".ids-filter-bar",
            ".ids-table-wrap",
            ".ids-dialog-backdrop",
            "@media (max-width: 920px)",
            "@media (max-width: 640px)",
        ):
            self.assertIn(selector, styles)


if __name__ == "__main__":
    unittest.main()
