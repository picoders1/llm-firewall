#!/bin/sh
# Render the edge configuration and, in TLS mode, refuse to start unless the
# certificate material is actually usable (ADR-026 §25).
#
# ## Why this replaces nginx's own template mechanism
#
# The base image's entrypoint runs envsubst over every file in
# /etc/nginx/templates with a prefix filter. Two things make that unsuitable
# here: the listener has to be *chosen* rather than all rendered, and the filter
# is a prefix match — a variable added later without the EDGE_ prefix would be
# silently substituted, and `$binary_remote_addr` becoming an empty string turns
# a per-client rate limit into a global one that throttles everybody as one
# client. Naming the substitutable variables explicitly removes that class of
# accident entirely.
#
# ## Why the checks are real rather than textual
#
# "ssl_certificate is present in the config" proves nothing: the file may be
# absent, unreadable, expired, or a certificate whose private half is a different
# key. Each of those produces a *different* failure, and two of them fail at
# first handshake rather than at startup — which is precisely the silent
# degradation a TLS deployment must not have. So the key is matched to the
# certificate by comparing public halves, and expiry is checked, before nginx is
# ever asked to load them.
set -eu

AVAILABLE=/etc/nginx/available
TARGET=/etc/nginx/conf.d
MODE="${EDGE_TLS_MODE:-off}"

: "${EDGE_RATE_PER_SECOND:=5}"
: "${EDGE_BURST:=10}"
: "${EDGE_CONN_PER_IP:=20}"
: "${EDGE_MAX_BODY:=256k}"
: "${EDGE_TLS_CERT:=/etc/nginx/tls/fullchain.pem}"
: "${EDGE_TLS_KEY:=/etc/nginx/tls/privkey.pem}"
: "${EDGE_TLS_PUBLIC_PORT:=8443}"
export EDGE_RATE_PER_SECOND EDGE_BURST EDGE_CONN_PER_IP EDGE_MAX_BODY
export EDGE_TLS_CERT EDGE_TLS_KEY EDGE_TLS_PUBLIC_PORT

# An explicit allow-list. Anything not named here — `$scheme`, `$host`,
# `$binary_remote_addr`, `$request_uri` — reaches nginx untouched.
VARS='$EDGE_RATE_PER_SECOND $EDGE_BURST $EDGE_CONN_PER_IP $EDGE_MAX_BODY $EDGE_TLS_CERT $EDGE_TLS_KEY $EDGE_TLS_PUBLIC_PORT'

fail() {
    echo "edge: FATAL: $*" >&2
    echo "edge: refusing to start. A TLS deployment must not fall back to plaintext." >&2
    exit 1
}

# The base image ships one; it would bind :80 alongside ours.
rm -f "$TARGET/default.conf"

case "$MODE" in
    off)
        LISTENER="$AVAILABLE/http.template"
        echo "edge: TLS is OFF — serving plain HTTP. Development and internal use only."
        ;;
    on)
        LISTENER="$AVAILABLE/tls.template"

        [ -f "$EDGE_TLS_CERT" ] || fail "certificate not found at $EDGE_TLS_CERT (mount it at run time)"
        [ -r "$EDGE_TLS_CERT" ] || fail "certificate at $EDGE_TLS_CERT is not readable"
        [ -f "$EDGE_TLS_KEY" ]  || fail "private key not found at $EDGE_TLS_KEY (mount it at run time)"
        [ -r "$EDGE_TLS_KEY" ]  || fail "private key at $EDGE_TLS_KEY is not readable"

        cert_pub=$(openssl x509 -in "$EDGE_TLS_CERT" -noout -pubkey 2>/dev/null) \
            || fail "the file at $EDGE_TLS_CERT is not a PEM certificate"
        key_pub=$(openssl pkey -in "$EDGE_TLS_KEY" -pubout 2>/dev/null) \
            || fail "the file at $EDGE_TLS_KEY is not a readable PEM private key"
        [ "$cert_pub" = "$key_pub" ] \
            || fail "the private key does not match the certificate"

        openssl x509 -in "$EDGE_TLS_CERT" -noout -checkend 0 >/dev/null 2>&1 \
            || fail "the certificate has expired"

        subject=$(openssl x509 -in "$EDGE_TLS_CERT" -noout -subject)
        notafter=$(openssl x509 -in "$EDGE_TLS_CERT" -noout -enddate)
        # Subject and expiry only. The certificate body is public, but there is no
        # reason for a startup log to carry it, and the KEY path is the only thing
        # said about the key — never its contents (§21).
        echo "edge: TLS is ON  cert=$EDGE_TLS_CERT key=$EDGE_TLS_KEY"
        echo "edge:   $subject"
        echo "edge:   $notafter"
        ;;
    *)
        fail "EDGE_TLS_MODE must be 'on' or 'off', got '$MODE'"
        ;;
esac

envsubst "$VARS" < "$AVAILABLE/zones.template"              > "$TARGET/00-zones.conf"
envsubst "$VARS" < "$AVAILABLE/gateway.locations.template"  > "$TARGET/gateway.locations.inc"
envsubst "$VARS" < "$LISTENER"                              > "$TARGET/10-server.conf"

# Output is passed through rather than discarded and re-run: nginx's message is
# the only thing that says WHICH directive it disliked, and an error path that
# hides the error is worse than no error path.
if ! nginx -t 2>&1; then
    fail "the rendered configuration was rejected by nginx (see above)"
fi
