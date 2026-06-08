"""Initialize or update a user with any role.

Usage:
    python -m app.scripts.init_admin --username admin --password 'change-me'
    python -m app.scripts.init_admin --username analyst1 --password 'pass1234' --role analyst
    python -m app.scripts.init_admin --username viewer1 --password 'pass1234' --role viewer
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
from typing import Sequence

from sqlalchemy import select

from app.core.security import hash_password
from app.models.base import close_db, get_session_factory, init_db
from app.models.models import User

VALID_ROLES = ("admin", "analyst", "viewer")


async def upsert_user(
    username: str,
    password: str,
    role: str = "admin",
    email: str | None = None,
    tenant_id: str = "default",
) -> str:
    """Create or update an active user and return its id."""
    await init_db()
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user:
            old_role = user.role
            user.hashed_password = hash_password(password)
            user.role = role
            user.tenant_id = tenant_id
            user.is_active = True
            if email:
                user.email = email
            print(f"WARNING: User '{username}' already exists (role={old_role}), updating to role={role}")
        else:
            user = User(
                username=username,
                email=email,
                hashed_password=hash_password(password),
                role=role,
                tenant_id=tenant_id,
                is_active=True,
            )
            session.add(user)
        await session.commit()
        await session.refresh(user)
        return user.id


# Keep backward compat alias
upsert_admin = upsert_user


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize or update a user.")
    parser.add_argument("--username", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", default="", help="Password (prompted if empty)")
    parser.add_argument("--role", default="admin", choices=VALID_ROLES, help="User role (default: admin)")
    parser.add_argument("--email", default=None, help="Email (optional)")
    parser.add_argument("--tenant-id", default="default", help="Tenant ID (default: default)")
    return parser.parse_args(argv)


async def _amain(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    password = args.password or getpass.getpass(f"{args.role} password: ")
    if len(password) < 8:
        raise SystemExit("Password must be at least 8 characters.")
    user_id = await upsert_user(
        username=args.username,
        password=password,
        role=args.role,
        email=args.email,
        tenant_id=args.tenant_id,
    )
    await close_db()
    print(f"User ready: username={args.username} role={args.role} user_id={user_id} tenant_id={args.tenant_id}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())
