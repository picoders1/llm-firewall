"""Database connectivity foundation.

Phase 0 establishes the engine, session factory and a readiness probe — the
connectivity architecture and the migration mechanism. **No schema is created
here.** The audit tables in docs/11-data-model.md arrive with the persistence
task later in Phase 0; creating tables ahead of the code that writes them would
be schema nobody can justify.

Nothing is ever created by ``Base.metadata.create_all()`` outside test fixtures:
a schema that exists only because the app booted is a schema nobody can review or
roll back (ADR-012).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import structlog
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config.settings import Settings

logger = structlog.get_logger(__name__)

# Bounds how long a single statement may hold the request path. Applied via the
# asyncpg command timeout rather than a server-side setting so it travels with
# the client.
STATEMENT_TIMEOUT_S = 5.0


class Base(DeclarativeBase):
    """Declarative base for audit and evaluation models."""


@dataclass(frozen=True, slots=True)
class DatabaseReadiness:
    """What one readiness probe learned about the audit store."""

    reachable: bool
    # `None` means the connection worked but Alembic's bookkeeping table is not
    # there — a database that has never been migrated. Distinguished from
    # unreachable so an operator is not sent to debug the network.
    revision: str | None


class Database:
    """Owns the engine and session factory for the process lifetime."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> Database | None:
        """Build a database handle, or ``None`` when persistence is disabled.

        Returning ``None`` rather than a null-object keeps "there is no audit
        sink configured" an explicit, visible state at every call site.
        """
        if not settings.persist_events or settings.database_url is None:
            return None

        engine = create_async_engine(
            settings.database_url.get_secret_value(),
            pool_size=settings.database_pool_size,
            pool_pre_ping=True,
            connect_args={"command_timeout": STATEMENT_TIMEOUT_S},
            echo=False,  # echo would log SQL parameters, which may carry content
        )
        return cls(engine)

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._sessionmaker() as session:
            yield session

    async def check(self) -> bool:
        """Readiness probe. Returns False rather than raising: readiness reports
        a per-check breakdown and must not itself fail with a 500."""
        return (await self.readiness()).reachable

    async def readiness(self) -> DatabaseReadiness:
        """Reachability and applied schema revision, in one connection.

        Both facts in one round trip because `/ready` is polled by an
        orchestrator on a short interval, and two connections per probe is a
        cost paid forever for information that arrives together anyway.

        Deliberately cheap: `SELECT 1` and a single-row read of Alembic's own
        bookkeeping table. Readiness must not become a load source (ADR-027).
        """
        try:
            async with self._engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
                try:
                    result = await connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    )
                    revision = result.scalar_one_or_none()
                except SQLAlchemyError:
                    # Reachable but un-migrated: the table itself is absent. A
                    # distinct state from "unreachable", and the one a fresh
                    # database is in before the first `alembic upgrade`.
                    revision = None
        except Exception as exc:
            logger.warning("database_check_failed", error_kind=type(exc).__name__)
            return DatabaseReadiness(reachable=False, revision=None)
        return DatabaseReadiness(reachable=True, revision=revision)

    async def aclose(self) -> None:
        await self._engine.dispose()
