"""Characterization tests for agent_service.find_session_by_prefix.

Locks the lookup contract before the fetch-100-and-filter-in-Python body is
replaced by an indexed SQL prefix query (P4 efficiency cleanup):

  - matches by case-insensitive id prefix
  - returns the most recently created session on an ambiguous prefix
  - returns None when nothing matches
  - a SQL LIKE wildcard in the prefix is treated literally (no broadened match)
"""

import asyncio
from datetime import datetime, timedelta, timezone

from app.database.session import get_sessionmaker
from app.models import AgentSession
from app.services.agent_service import find_session_by_prefix


def test_find_session_by_prefix_contract():
    async def _run():
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        async with get_sessionmaker()() as session:
            session.add_all(
                [
                    AgentSession(
                        id="abc11111-1111-1111-1111-111111111111",
                        target_url="https://lab.example",
                        created_at=base,
                    ),
                    AgentSession(
                        id="abc99999-9999-9999-9999-999999999999",
                        target_url="https://lab.example",
                        created_at=base + timedelta(minutes=5),
                    ),
                    AgentSession(
                        id="zzz00000-0000-0000-0000-000000000000",
                        target_url="https://lab.example",
                        created_at=base + timedelta(minutes=1),
                    ),
                ]
            )
            await session.commit()

        async with get_sessionmaker()() as session:
            # unique prefix
            r = await find_session_by_prefix(session, "zzz0")
            assert r is not None and r.id.startswith("zzz0")

            # case-insensitive
            r = await find_session_by_prefix(session, "ZZZ0")
            assert r is not None and r.id.startswith("zzz0")

            # ambiguous prefix -> most recently created wins
            r = await find_session_by_prefix(session, "abc")
            assert r is not None and r.id.startswith("abc9")

            # no match
            assert await find_session_by_prefix(session, "nope") is None

            # a LIKE wildcard must NOT broaden the match
            assert await find_session_by_prefix(session, "ab%") is None

    asyncio.run(_run())
