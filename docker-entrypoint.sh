#!/bin/sh
# A mounted Render disk is root-owned; fix that, then drop privileges.
set -e
mkdir -p /app/data /app/logs
chown -R app:app /app/data /app/logs 2>/dev/null || true
exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
