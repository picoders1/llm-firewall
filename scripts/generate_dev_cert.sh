#!/usr/bin/env bash
# Generate a DEVELOPMENT-ONLY TLS certificate for the reference edge (ADR-026).
#
# Writes to deploy/certs/, which is gitignored as a directory — so `git add
# deploy/certs` cannot succeed by accident — and excluded from every Docker build
# context, so the key can never be baked into an image layer.
#
# ## Why this is generated rather than committed
#
# A committed private key is a private key in the history forever, and the fact
# that it is "only for development" is a property of intent, not of the file. The
# moment someone reaches for it in a hurry it becomes a production key with a
# public private half. Generating takes two seconds and removes the temptation.
#
# ## Why it is obviously not production-valid
#
# Self-signed, 30 days, and the subject says so in words. A browser will refuse
# it and an operator reading `openssl x509 -text` sees DEVELOPMENT in the CN.
# Making a development certificate look production-valid is how one ends up in
# production (§5).
set -euo pipefail

CERT_DIR="${CERT_DIR:-deploy/certs}"
DAYS="${DAYS:-30}"
# SANs the local stack is reached by. `localhost` for the host, `edge` for
# container-to-container, `127.0.0.1` for tools that skip DNS.
HOSTS="${HOSTS:-DNS:localhost,DNS:edge,DNS:firewall.localhost,IP:127.0.0.1}"

command -v openssl >/dev/null || {
    echo "openssl is required and was not found on PATH" >&2
    exit 1
}

mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/privkey.pem" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "$CERT_DIR/privkey.pem already exists; set FORCE=1 to replace it"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=DEVELOPMENT ONLY - llm-firewall local edge/O=llm-firewall development" \
    -addext "subjectAltName=$HOSTS" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    2>/dev/null

# The key is readable by its owner only. nginx reads it as root before dropping
# to the worker user, so 600 is sufficient and 644 would be a finding.
chmod 600 "$CERT_DIR/privkey.pem"
chmod 644 "$CERT_DIR/fullchain.pem"

echo "Wrote DEVELOPMENT-ONLY certificate to $CERT_DIR/ (valid $DAYS days)"
openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -subject -dates -ext subjectAltName |
    sed 's/^/  /'
echo
echo "  This certificate is self-signed and will be refused by browsers and by"
echo "  any client that validates. That is intended. Production certificates come"
echo "  from your CA and are mounted at run time — see ADR-026."
