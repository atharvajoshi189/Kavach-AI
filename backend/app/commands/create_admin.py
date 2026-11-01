"""Secure CLI bootstrap command for initial administrator provisioning.

Security Note:
    Passwords are never accepted as command-line arguments to prevent exposure
    via process listing (ps/Get-Process) and shell history (.bash_history/PSReadLine).
    Hidden, interactive prompt entry via `getpass` is required.

Usage:
    python -m app.commands.create_admin --email admin@aegismesh.internal --username admin
"""

import argparse
import asyncio
import getpass
import sys
from sqlalchemy import or_, select
from app.core.audit import AuditEvent, log_audit_event
from app.core.security import hash_password, validate_password_strength
from app.database.session import AsyncSessionLocal
from app.models.user import User, UserRole


async def provision_admin(email: str, username: str, password: str) -> None:
    """Creates a platform administrator user directly in the database."""
    # Validate password complexity
    try:
        validate_password_strength(password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    async with AsyncSessionLocal() as session:
        # Check if email or username already exists
        query = select(User).where(
            or_(
                User.email == email.lower(),
                User.username == username.lower(),
            )
        )
        result = await session.execute(query)
        existing_user = result.scalar_one_or_none()

        if existing_user:
            if existing_user.role == UserRole.ADMIN:
                print(f"Notice: User '{username}' ({email}) already exists and is an administrator.")
                return
            else:
                print(f"Error: User '{username}' ({email}) already exists with role '{existing_user.role.value}'.", file=sys.stderr)
                sys.exit(1)

        admin_user = User(
            email=email.lower(),
            username=username.lower(),
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
        )

        session.add(admin_user)
        await session.commit()
        await session.refresh(admin_user)

        log_audit_event(
            AuditEvent.ADMIN_BOOTSTRAP,
            user_id=str(admin_user.id),
            username=admin_user.username,
            details={"assigned_role": UserRole.ADMIN.value},
        )

        print(f"Administrator '{admin_user.username}' ({admin_user.email}) successfully provisioned [ID: {admin_user.id}].")


def main():
    parser = argparse.ArgumentParser(
        description="AegisMesh Administrator Bootstrap Tool",
        epilog="Passwords must be entered via secure hidden prompt (never passed on CLI).",
    )
    parser.add_argument("--email", required=False, help="Administrator email address")
    parser.add_argument("--username", required=False, help="Administrator username")

    args = parser.parse_args()

    email = (args.email or input("Enter Admin Email: ")).strip()
    username = (args.username or input("Enter Admin Username: ")).strip()

    if not email or not username:
        print("Error: email and username are required.", file=sys.stderr)
        sys.exit(1)

    # Secure hidden password entry
    password = getpass.getpass("Enter Admin Password: ").strip()
    confirm_password = getpass.getpass("Confirm Admin Password: ").strip()

    if not password:
        print("Error: password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if password != confirm_password:
        print("Error: passwords do not match.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(provision_admin(email, username, password))


if __name__ == "__main__":
    main()
