#!/bin/sh
# ASSAS eve.json rotation (Sprint 2, PBI-13).
#
# Replaces logrotate for eve.json. Rename-based rotation + SIGHUP reopen
# (man suricata: "SIGHUP causes Suricata to close and re-open all log files").
# NEVER compresses or deletes: retention is owned solely by the alert ingester's
# checkpoint-gated reaper (appliance/alerts.py), which removes a rotated eve file
# only after it is fully consumed. Because this script only renames, it is safe
# to run while the ingester is stopped — rotated files simply accumulate on disk
# until the ingester comes back and consumes them (no data is ever lost).
#
# Invoked periodically by assas-suricata-rotate.timer. Rotates only when
# eve.json is at/over the size threshold, unless --force is given.
set -eu

EVE="${ASSAS_EVE_PATH:-/var/log/suricata/eve.json}"
MAX_BYTES="${ASSAS_EVE_MAX_BYTES:-52428800}"        # 50 MiB
SERVICE="${ASSAS_SURICATA_SERVICE:-assas-suricata.service}"
FORCE="${1:-}"

[ -f "$EVE" ] || { echo "rotate-eve: $EVE absent, nothing to do"; exit 0; }

size=$(stat -c %s "$EVE")
[ "$size" -gt 0 ] || { echo "rotate-eve: $EVE empty, skipping"; exit 0; }

if [ "$FORCE" != "--force" ] && [ "$size" -lt "$MAX_BYTES" ]; then
    echo "rotate-eve: $EVE size $size < $MAX_BYTES, skipping"
    exit 0
fi

ts=$(date -u +%Y%m%d-%H%M%S)
rotated="${EVE}-${ts}"
[ -e "$rotated" ] && rotated="${EVE}-$(date -u +%Y%m%d-%H%M%S-%N)"

# Rename, then signal Suricata to reopen (it keeps writing to the renamed file
# via its open fd until it processes the signal, so no events are lost).
mv "$EVE" "$rotated"
systemctl kill -s HUP "$SERVICE"
echo "rotate-eve: rotated $EVE -> $rotated ($size bytes); sent SIGHUP to $SERVICE"
