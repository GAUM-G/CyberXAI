"""Interactive local account management for the defender dashboard.

For local recovery only; normal account creation uses the signup page:
    python -m dashboard.manage_users reset-password --email analyst@gmail.com
"""

from __future__ import annotations

import argparse
import getpass
import sqlite3

from .auth import auth_db_path, create_user, promote_admin, reset_password, set_user_active


def _new_password() -> str:
    password = getpass.getpass("New dashboard password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise ValueError("Passwords did not match")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage private dashboard analyst accounts")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("create-user", "reset-password", "disable-user", "promote-admin"):
        sub = commands.add_parser(command)
        sub.add_argument("--email", required=True)
    args = parser.parse_args()
    db_path = auth_db_path()
    try:
        if args.command == "create-user":
            create_user(db_path, args.email, _new_password())
            print(f"Created dashboard user {args.email!r} in {db_path}")
        elif args.command == "reset-password":
            if not reset_password(db_path, args.email, _new_password()):
                raise ValueError("Dashboard user does not exist")
            print(f"Password reset for {args.email!r}; existing sessions revoked")
        elif args.command == "promote-admin":
            if not promote_admin(db_path, args.email):
                raise ValueError("Dashboard user does not exist")
            print(f"Administrator access enabled for {args.email!r}; existing sessions revoked")
        else:
            if not set_user_active(db_path, args.email, False):
                raise ValueError("Dashboard user does not exist")
            print(f"Disabled dashboard user {args.email!r}; existing sessions revoked")
    except (ValueError, sqlite3.IntegrityError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
