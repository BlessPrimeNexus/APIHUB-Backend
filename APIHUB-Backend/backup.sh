#!/bin/sh
# Consistent online backup of the SQLite database. Usage: ./backup.sh [output_dir]
set -eu
OUT="${1:-./backups}"; mkdir -p "$OUT"
DB="${DATABASE_PATH:-./data/apihub.db}"
STAMP=$(date +%Y%m%d-%H%M%S)
node --disable-warning=ExperimentalWarning -e "
const {DatabaseSync}=require('node:sqlite');
const d=new DatabaseSync(process.argv[1]); d.exec(\"VACUUM INTO '\" + process.argv[2].replace(/'/g,\"''\") + \"'\"); d.close();" "$DB" "$OUT/apihub-$STAMP.db"
echo "Backup written: $OUT/apihub-$STAMP.db"
