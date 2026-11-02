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
# Invoked periodically by assas-suricata-rotate.timer, and occasionally by hand
# for testing. A shared flock serialises those so the timer and a manual/forced
# run can never rotate at the same time. Rotated names are made collision-proof.
set -eu

EVE="${ASSAS_EVE_PATH:-/var/log/suricata/eve.json}"
MAX_BYTES="${ASSAS_EVE_MAX_BYTES:-52428800}"        # 50 MiB
SERVICE="${ASSAS_SURICATA_SERVICE:-assas-suricata.service}"
LOCK="${ASSAS_EVE_ROTATE_LOCK:-/run/assas-suricata-rotate.lock}"
FORCE="${1:-}"

# Serialise all rotations (timer vs. manual). Wait up to 30s for the lock.
exec 9>"$LOCK"
if ! flock -w 30 9; then
    echo "rotate-eve: another rotation holds $LOCK, skipping"
    exit 0
fi

[ -f "$EVE" ] || { echo "rotate-eve: $EVE absent, nothing to do"; exit 0; }

size=$(stat -c %s "$EVE")
[ "$size" -gt 0 ] || { echo "rotate-eve: $EVE empty, skipping"; exit 0; }

if [ "$FORCE" != "--force" ] && [ "$size" -lt "$MAX_BYTES" ]; then
    echo "rotate-eve: $EVE size $size < $MAX_BYTES, skipping"
    exit 0
fi

# Collision-proof target name (unique even for repeated runs in the same second).
base="${EVE}-$(date -u +%Y%m%d-%H%M%S)"
rotated="$base"
n=0
while [ -e "$rotated" ]; do
    n=$((n + 1))
    rotated="${base}.${n}"
done

# Rename, then signal Suricata to reopen (it keeps writing to the renamed file
# via its open fd until it processes the signal, so no events are lost).
mv "$EVE" "$rotated"
systemctl kill -s HUP "$SERVICE"
echo "rotate-eve: rotated $EVE -> $rotated ($size bytes); sent SIGHUP to $SERVICE"
