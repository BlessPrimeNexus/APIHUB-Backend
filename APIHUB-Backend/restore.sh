#!/bin/sh
# Restore a backup. STOP the server first. Usage: ./restore.sh backups/apihub-XXXX.db
set -eu
SRC="$1"; DB="${DATABASE_PATH:-./data/apihub.db}"
[ -f "$SRC" ] || { echo "Backup not found: $SRC"; exit 1; }
[ -f "$DB" ] && cp "$DB" "$DB.before-restore.$(date +%s)"
rm -f "$DB-wal" "$DB-shm"; cp "$SRC" "$DB"
echo "Restored $SRC -> $DB (previous DB kept as .before-restore.*)"
