#!/bin/sh
# Download DB-IP Lite Country MMDB database.
# License: CC BY 4.0 (attribution required).
# Run monthly to keep the database fresh.
#
# Usage:
#   ./scripts/update-geoip.sh [output_dir]
#
# Default output: /data/geoip/country.mmdb (container) or ./geoip/ (local)

set -eu

OUTPUT_DIR="${1:-/data/geoip}"
MMDB_FILE="$OUTPUT_DIR/country.mmdb"

# DB-IP updates on the 1st of each month. Build the URL for the current month.
YEAR=$(date +%Y)
MONTH=$(date +%m)
URL="https://download.db-ip.com/free/dbip-country-lite-${YEAR}-${MONTH}.mmdb.gz"

mkdir -p "$OUTPUT_DIR"

echo "Downloading DB-IP Lite Country MMDB from $URL ..."
TMPFILE=$(mktemp)
if curl -fsSL --retry 3 --max-time 60 "$URL" -o "$TMPFILE.gz"; then
    gunzip -f "$TMPFILE.gz"
    mv "$TMPFILE" "$MMDB_FILE"
    echo "Updated $MMDB_FILE ($(wc -c < "$MMDB_FILE") bytes)"
else
    echo "Download failed — keeping existing database if present"
    rm -f "$TMPFILE" "$TMPFILE.gz"
    exit 1
fi
