#!/bin/sh
set -eu
: "${GUIDED_H20_WEBHOOK_TOKEN:?P20 webhook credential is required}"
umask 077
cat > /run/p20/webhook-token <<EOF
${GUIDED_H20_WEBHOOK_TOKEN}
EOF
unset GUIDED_H20_WEBHOOK_TOKEN
exec /bin/alertmanager "$@"
