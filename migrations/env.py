"""Alembic environment.

Reads the database URL from application settings rather than `alembic.ini`, so
the credential lives in exactly one place — the environment (ADR-011).

Migrations run as a separate deployment step under a role that may alter schema,
never on application startup: N replicas starting together would race, and a
failed migration would become a crash loop instead of a clear failure
(docs/17-deployment-architecture.md).
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy.pool import NullPool

from app.config.settings import get_settings

# Import every model module here so autogenerate sees the full metadata.
from app.database import models as _models  # noqa: F401  (registers tables on Base)
from app.database.session import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    settings = get_settings()
    if settings.database_url is None:
        raise RuntimeError(
            "FIREWALL_DATABASE_URL is not set. Migrations need a database URL; "
            "it is read from the environment, never from alembic.ini."
        )
    return settings.database_url.get_secret_value()


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting — useful for review and for DBAs."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: object) -> None:
    context.configure(
        connection=connection,  # type: ignore[arg-type]
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
