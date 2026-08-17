# syntax=docker/dockerfile:1
#
# Multi-stage build. The runtime stage carries the virtualenv and the application
# only — no compiler, no build headers, no uv, no tests.
# Security baseline: docs/10-security-model.md.
#
# The base image is pinned by digest, not by tag: a tag is mutable, so a build
# that "worked yesterday" can silently become a different base image today.
# Refreshing the digest is a deliberate, reviewable change.
ARG PYTHON_IMAGE=python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

# The virtualenv is built at its FINAL path. Console scripts embed an absolute
# interpreter path in their shebang, so a venv created at /build/.venv and copied
# to /app/.venv produces "no such file or directory" at exec time — a failure
# that looks like a missing binary when the binary is plainly there.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /build

# Dependencies first, in their own layer: they change far less often than the
# source, so an application edit does not re-resolve the world.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

COPY app ./app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

# curl is present solely for HEALTHCHECK; everything else is the base image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=builder --chown=root:root /app/.venv /app/.venv
COPY --chown=root:root app ./app
COPY --chown=root:root config ./config
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root alembic.ini ./

# Non-root, and the process cannot write to its own code: everything it needs is
# owned by root and read-only to `app`.
USER app

EXPOSE 8000

# Liveness only. Orchestrators route on /ready, which additionally waits for
# detector warm-up (docs/12-observability.md).
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
