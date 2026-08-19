#!/bin/sh
# Generates the development credential at container start.
#
# Deliberately NOT a committed .htpasswd file. A password hash in git is a
# credential in git, however weak — and this repository's pre-commit secret scan
# is there precisely to stop that. The value comes from the environment, has an
# obviously-development default, and lives only in the container's tmpfs.
#
# Written to /tmp because the container runs with a read-only root filesystem
# (docs/10-security-model.md). Errors are NOT swallowed: a silent failure here
# leaves nginx crash-looping with an empty log, which is a genuinely miserable
# thing to debug.
set -eu

: "${DEV_OPERATOR_USER:=operator}"
: "${DEV_OPERATOR_PASSWORD:=development-only}"

htpasswd -bcB /tmp/operators.htpasswd "$DEV_OPERATOR_USER" "$DEV_OPERATOR_PASSWORD"
echo "console-proxy: development credential ready for user '${DEV_OPERATOR_USER}'"
