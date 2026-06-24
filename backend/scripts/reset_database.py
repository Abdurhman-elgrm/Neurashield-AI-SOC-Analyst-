"""
Full database reset + demo seed script.

Run once to wipe EVERYTHING and create a fresh demo environment:

    cd backend
    python scripts/reset_database.py

WARNING: This drops all user accounts, tenants, alerts, agents, and all
other data.  There is no undo.  Run only when you want a clean slate.
"""
import asyncio
import sys
import os

# Allow running from repo root or backend/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from app.core.config import settings
from app.services.demo_service import _get_or_create_tenant, _get_or_create_user, _seed_all


WIPE_ORDER = [
    # dependent tables first
    "playbook_steps",
    "playbook_runs",
    "playbooks",
    "playbook_auto_config",
    "playbook_template_steps",
    "playbook_templates",
    "suppression_rules",
    "audit_logs",
    "heartbeats",
    "alerts",
    "investigations",
    "detection_rules",
    "refresh_tokens",
    "tenant_members",
    "invitations",
    "agents",
    "tenants",
    "users",
]


async def main() -> None:
    print("=" * 60)
    print("  NEURASHIELD — Full Database Reset + Demo Seed")
    print("=" * 60)
    print()
    print("WARNING: This will DELETE ALL DATA in the database.")
    confirm = input("Type 'yes' to continue: ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        print("\n[1/3] Wiping all tables...")
        for table in WIPE_ORDER:
            try:
                await db.execute(text(f"TRUNCATE TABLE {table} CASCADE"))
                print(f"      ✓ {table}")
            except Exception as e:
                # Table might not exist yet or has no rows — skip
                print(f"      - {table} (skipped: {e})")
                await db.rollback()
        await db.commit()
        print("      Done.\n")

        print("[2/3] Creating demo tenant + user...")
        tenant = await _get_or_create_tenant(db)
        user   = await _get_or_create_user(db, tenant)
        print(f"      Tenant: {tenant.name} (slug={tenant.slug})")
        print(f"      User:   {user.email}")
        print("      Done.\n")

        print("[3/3] Seeding demo data (agents, alerts, investigations, playbooks...)...")
        await _seed_all(db, tenant, user)
        print("      Done.\n")

    await engine.dispose()

    print("=" * 60)
    print("  Reset complete!")
    print(f"  Demo login available at: POST /api/v1/auth/demo")
    print(f"  Demo email: {user.email}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
