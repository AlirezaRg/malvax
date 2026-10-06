"""Admin CLI: create the first user. There is no self-registration endpoint.

Usage:
    python -m malvax.manage create-user --username admin --role admin
(password is read interactively, never as a CLI argument, so it does not end up in shell
history or process listings)
"""

from __future__ import annotations

import argparse
import getpass
import sys

from malvax.auth import Role
from malvax.config import Settings
from malvax.db import make_engine, make_session_factory
from malvax.service import UsernameTakenError, create_user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m malvax.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="create a user (prompts for the password)")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=[r.value for r in Role], required=True)
    args = parser.parse_args(argv)

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("passwords do not match", file=sys.stderr)
        return 1

    settings = Settings.from_env()
    factory = make_session_factory(make_engine(settings.database_url))
    with factory() as session:
        try:
            user = create_user(session, args.username, password, Role(args.role))
        except (ValueError, UsernameTakenError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print(f"created user {user.username!r} with role {user.role}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
