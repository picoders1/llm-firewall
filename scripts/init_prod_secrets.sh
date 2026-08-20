#!/usr/bin/env bash
# Create the secret FILES the reference production stack mounts (ADR-028).
#
# Writes to deploy/secrets/, which is gitignored as a directory and excluded
# from every Docker build context — so none of this can reach a commit or an
# image layer.
#
# ## Why files rather than environment variables
#
# An environment variable is readable by anything that can run `docker inspect`,
# anything that can read /proc/<pid>/environ, and every crash reporter that
# dumps the environment on the way down. A mounted file is readable by the
# process and by root, and it does not appear in any of those places.
#
# ## What this script does NOT do
#
# It generates a caller credential and a database password, because those are
# this deployment's own. It does NOT invent an upstream provider key — that
# comes from your provider — and it writes an empty placeholder you must fill.
set -euo pipefail

DIR="${SECRETS_DIR:-deploy/secrets}"
PG_USER="${POSTGRES_USER:-firewall}"
PG_DB="${POSTGRES_DB:-firewall}"
# The uid the application image runs as (deploy/docker/Dockerfile: `useradd
# --uid 10001 app`). The container is non-root and drops every capability, so it
# has no DAC_OVERRIDE and cannot read a file it does not own.
APP_UID="${APP_UID:-10001}"

mkdir -p "$DIR"
# 0700: the directory is what protects these on the HOST. Another unprivileged
# user cannot traverse it, whatever the files inside are set to.
chmod 700 "$DIR"

# Two ways to make a secret readable by a non-root container, in order of
# preference:
#
#   1. chown to the container's uid, keeping mode 0600. Needs privilege on the
#      host, and is what a real deployment does.
#   2. mode 0444 inside a 0700 directory. No privilege needed; the file itself is
#      world-readable but nothing can reach it without traversing the directory.
#
# Granting the container DAC_OVERRIDE instead was considered and rejected: that
# is the capability to bypass every file permission in the container, handed over
# to read three files.
readable_by_container() {
    local path="$1"
    if chown "$APP_UID" "$path" 2>/dev/null; then
        chmod 600 "$path"
        return 0
    fi
    chmod 444 "$path"
    return 1
}

FELL_BACK=0

write() {
    local name="$1" value="$2"
    if [ -f "$DIR/$name" ] && [ "${FORCE:-0}" != "1" ]; then
        echo "  $name already exists (FORCE=1 to replace)"
        return
    fi
    # Unlinked first: the fallback mode is 0444, and `>` cannot truncate a
    # read-only file even for its owner. Without this, rotation fails on every
    # deployment that took the unprivileged path — which is the one that most
    # needs rotation to work.
    rm -f "$DIR/$name"
    printf '%s' "$value" > "$DIR/$name"
    readable_by_container "$DIR/$name" || FELL_BACK=1
    echo "  wrote $DIR/$name"
}

pg_password="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"

write postgres_password "$pg_password"
# `postgres` is the service name on the internal `data` network; it resolves
# nowhere else, which is the point of that network being internal.
write database_url "postgresql+asyncpg://${PG_USER}:${pg_password}@postgres:5432/${PG_DB}"

if [ ! -f "$DIR/caller_api_keys" ] || [ "${FORCE:-0}" = "1" ]; then
    out="$(uv run python scripts/generate_caller_key.py "${CALLER_ID:-app}")"
    raw="$(echo "$out" | sed -n '4p' | tr -d ' ')"
    digest="$(echo "$out" | sed -n '7p' | tr -d ' ' | sed 's/FIREWALL_CALLER_API_KEYS=//')"
    rm -f "$DIR/caller_api_keys"
    printf '%s' "$digest" > "$DIR/caller_api_keys"
    readable_by_container "$DIR/caller_api_keys" || FELL_BACK=1
    echo "  wrote $DIR/caller_api_keys"
    echo
    echo "  ---- give this to the calling application, once; it is not recoverable ----"
    echo "    $raw"
    echo "  --------------------------------------------------------------------------"
fi

if [ ! -f "$DIR/upstream_api_key" ] || [ "${FORCE:-0}" = "1" ]; then
    rm -f "$DIR/upstream_api_key"
    # An empty file, not a fake key: the gateway must fail loudly against a real
    # provider rather than send a plausible-looking credential. Harmless against
    # the bundled mock, which authenticates nobody.
    : > "$DIR/upstream_api_key"
    readable_by_container "$DIR/upstream_api_key" || FELL_BACK=1
    echo "  wrote $DIR/upstream_api_key (EMPTY — put your provider key in it)"
fi

echo
echo "Secrets are in $DIR/. They are gitignored and excluded from build contexts."
echo "Nothing here belongs in prod.env, which is not secret."

if [ "$FELL_BACK" = "1" ]; then
    cat <<'NOTE'

  NOTE: could not chown the secret files to the container uid, so they were set
  to mode 0444 inside a 0700 directory. Another unprivileged user on this host
  cannot traverse the directory to reach them, but the files themselves are
  world-readable if the directory mode is ever relaxed.

  For a real deployment, run this as root (or chown -R 10001 the directory) so
  the files stay 0600 — or use a platform with first-class secret support:
  Swarm honours uid/gid/mode on a secret reference, and Kubernetes sets
  ownership from the pod's fsGroup.
NOTE
fi
