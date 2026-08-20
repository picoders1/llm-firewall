"""Which schema revision this code was written against.

Read from Alembic's own script directory rather than hard-coded, so the answer
cannot drift from the migrations actually shipped: adding a revision changes it
automatically, and forgetting to update a constant is not a failure mode that
exists.

Resolved once and cached. `/ready` is polled on a short interval and this walks
a directory; doing it per probe would make the readiness endpoint a source of
filesystem load for a value that cannot change while the process runs.

Returns `None` rather than raising when the migrations tree is absent — a source
checkout run from an unusual working directory, or a slimmed image. Readiness
then reports the *applied* revision without asserting a match, which is honest:
"I cannot tell" is different from "they differ", and only one of them is a
deployment error.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# app/database/migrations.py -> app/database -> app -> repository root
_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def expected_schema_revision() -> str | None:
    """The head revision of the migrations shipped with this code."""
    config_path = _ROOT / "alembic.ini"
    script_path = _ROOT / "migrations"
    if not config_path.is_file() or not script_path.is_dir():
        logger.info("migration_head_unavailable", reason="migrations tree not found")
        return None

    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config(str(config_path))
        config.set_main_option("script_location", str(script_path))
        heads = ScriptDirectory.from_config(config).get_heads()
    except Exception as exc:  # pragma: no cover - defensive; alembic is a hard dep
        logger.warning("migration_head_unavailable", error_kind=type(exc).__name__)
        return None

    if len(heads) != 1:
        # Multiple heads mean an un-merged branch. Reporting "unknown" is right:
        # there is no single revision this code expects, and picking one would
        # invent an answer.
        logger.warning("migration_heads_ambiguous", count=len(heads))
        return None
    return heads[0]


__all__ = ["expected_schema_revision"]
