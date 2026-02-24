#!/bin/sh
# rotate-audit-log.sh — Rotate the Coraza WAF audit log.
#
# Coraza doesn't support log reopening (no SIGHUP), so we use copytruncate:
# copy the log, truncate the original. waf-api's offset tracking detects the
# size shrink and resets automatically.
#
# Settings match Caddy's log rotation:
#   roll_size:     256 MB  (rotate when file exceeds this)
#   roll_keep:     5       (keep at most 5 rotated files)
#   roll_keep_for: 2160h   (delete rotated files older than 90 days)
set -eu

LOG="/var/log/coraza-audit.log"
MAX_SIZE=$((256 * 1024 * 1024))  # 256 MB in bytes
KEEP=5
KEEP_DAYS=90

# Only rotate if the file exists and exceeds MAX_SIZE.
if [ ! -f "$LOG" ]; then
    exit 0
fi

size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
if [ "$size" -lt "$MAX_SIZE" ]; then
    exit 0
fi

timestamp=$(date +%Y%m%d-%H%M%S)
rotated="${LOG}.${timestamp}"

# Copy then truncate (copytruncate pattern).
cp "$LOG" "$rotated"
: > "$LOG"

echo "[rotate-audit-log] rotated $LOG ($size bytes) -> $rotated"

# Delete old rotated files beyond KEEP count.
# List rotated files newest-first, skip the first KEEP, delete the rest.
ls -t "${LOG}".* 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
    echo "[rotate-audit-log] removing excess: $old"
    rm -f "$old"
done

# Delete rotated files older than KEEP_DAYS.
find "$(dirname "$LOG")" -name "$(basename "$LOG").*" -mtime "+${KEEP_DAYS}" -exec rm -f {} \; 2>/dev/null
