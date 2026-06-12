"""Service-layer test: cross-org IDOR guard in ScanService.create_scan.

The guard at app/services/scan_crud.py rejects a RoeDocument whose
organization_id != user.organization_id.  Existing tests only hit the
*nonexistent doc* path; this test exercises the org-mismatch branch directly.
"""
import asyncio

import pytest
from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.models import Organization, RoeDocument, Role, User
from app.core.security import hash_password
from app.services.scan_crud import ScanService


def test_cross_org_roe_document_is_rejected():
    """Org-B user must not be able to use org-A's RoeDocument."""

    async def _run():
        # ── Step 1: seed two orgs, one user each, one RoeDocument in org A ──
        async with AsyncSessionLocal() as session:
            # Create a minimal role if none exist yet (this test bypasses the
            # app lifespan bootstrap that normally seeds roles).
            role = (await session.execute(select(Role).limit(1))).scalar_one_or_none()
            if role is None:
                role = Role(name="IDOR-Test-Role", permissions=[])
                session.add(role)
                await session.flush()

            org_a = Organization(
                name="Cross-Org-Test-A",
                slug="cross-org-test-a",
            )
            org_b = Organization(
                name="Cross-Org-Test-B",
                slug="cross-org-test-b",
            )
            session.add_all([org_a, org_b])
            await session.flush()

            user_a = User(
                organization_id=org_a.id,
                role_id=role.id,
                email="user-a@cross-org-idor.test",
                full_name="User A",
                hashed_password=hash_password("irrelevant"),
            )
            user_b = User(
                organization_id=org_b.id,
                role_id=role.id,
                email="user-b@cross-org-idor.test",
                full_name="User B",
                hashed_password=hash_password("irrelevant"),
            )
            session.add_all([user_a, user_b])
            await session.flush()

            roe_doc = RoeDocument(
                organization_id=org_a.id,
                filename="scope.pdf",
                extracted_text="scope",
                char_count=5,
            )
            session.add(roe_doc)
            await session.commit()

            orgA_doc_id = roe_doc.id
            orgB_user_id = user_b.id

        # ── Step 2: fresh session, try to use org-A doc as org-B user ──
        async with AsyncSessionLocal() as session:
            orgB_user = (
                await session.execute(select(User).where(User.id == orgB_user_id))
            ).scalar_one()

            service = ScanService(session)
            with pytest.raises(ValueError):
                await service.create_scan(
                    user=orgB_user,
                    target_url="http://127.0.0.1:9",
                    project_name="x",
                    project_id=None,
                    policy_payload={},
                    allowed_domains=[],
                    ip_address=None,
                    engagement_mode="external",
                    roe_document_id=orgA_doc_id,
                )

    asyncio.run(_run())
