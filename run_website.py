"""Run the standalone decoy website and then run this.

Usage:
    python run_website.py
    python run_website.py --host 127.0.0.1 --port 8090
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone decoy website")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()

    from website.app import start_website

    start_website(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
