#!/bin/sh
# Fix ownership of a mounted volume (local Docker), then drop privileges. Render free plans have no disk.
set -e
mkdir -p /app/data /app/logs
chown -R app:app /app/data /app/logs 2>/dev/null || true
exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
