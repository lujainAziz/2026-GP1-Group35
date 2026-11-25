#!/bin/sh
# Representative 2-hour resource run WITHOUT the development agent (Sprint 2).
#
# The 13:37-15:37 UTC baseline ran with the development agent co-resident
# (~2.4 GB RSS), so its total-device memory does not validly judge the <4 GB
# target. This wrapper produces the agent-free measurement used to judge memory.
# It is ADDITIVE: it writes to evidence/resources/clean/ and never overwrites the
# retained baseline files (resource-2h.{csv,summary.json}, appliance-footprint.txt).
#
# It refuses to start while the development agent is present, and records agent
# presence every 30 s for the whole run; the result is valid only if
# agent-guard.log shows zero PRESENT entries.
#
# The agent's process name is not stored in the repo: pass it (a `pgrep -x`
# regex) in ASSAS_DEV_AGENT_PATTERN. The script aborts if it is not set.
#
# Run it after the development agent's session on the Pi has fully exited:
#   ASSAS_DEV_AGENT_PATTERN='<agent-process-name>' /home/assas/assas/appliance/tools/clean_resource_run.sh
set -eu

REPO=/home/assas/assas
OUTDIR="${ASSAS_RES_OUTDIR:-$REPO/docs/sprint-2/evidence/resources/clean}"
GUARD="$OUTDIR/agent-guard.log"
DURATION="${1:-7200}"
INTERVAL="${2:-10}"

AGENT_PATTERN="${ASSAS_DEV_AGENT_PATTERN:-}"
if [ -z "$AGENT_PATTERN" ]; then
    echo "ABORT: ASSAS_DEV_AGENT_PATTERN is not set; cannot check for the development agent." >&2
    echo "Set it to the agent's process-name pattern (pgrep -x regex) and re-run." >&2
    exit 1
fi

agent_present() {
    pgrep -x "$AGENT_PATTERN" >/dev/null 2>&1
}

mkdir -p "$OUTDIR"

if agent_present; then
    echo "ABORT: the development agent is still running — stop the session first." >&2
    pgrep -af "$AGENT_PATTERN" >&2 || true
    exit 1
fi

: > "$GUARD"
echo "$(date -u +%FT%TZ) start: agent absent (precheck passed)" >> "$GUARD"

# Background guard: record agent presence throughout the measurement.
(
    while :; do
        if agent_present; then
            echo "$(date -u +%FT%TZ) PRESENT"
        else
            echo "$(date -u +%FT%TZ) absent"
        fi
        sleep 30
    done
) >> "$GUARD" 2>&1 &
guard_pid=$!
trap 'kill "$guard_pid" 2>/dev/null || true' EXIT INT TERM

ASSAS_RES_OUTDIR="$OUTDIR" ASSAS_CAPTURE_IFACE="${ASSAS_CAPTURE_IFACE:-eth1}" \
    python3 "$REPO/appliance/tools/resource_sampler.py" "$DURATION" "$INTERVAL"

kill "$guard_pid" 2>/dev/null || true
echo "$(date -u +%FT%TZ) end" >> "$GUARD"

# grep -c prints "0" AND exits 1 when there is no match; `|| echo 0` would then
# append a second line and break the numeric test below (false warning). Capture
# the single count and default to 0 only when grep could not read the file.
present=$(grep -c ' PRESENT$' "$GUARD" 2>/dev/null) || present=0
[ -n "$present" ] || present=0
echo "clean run finished. agent-PRESENT samples: $present (must be 0 for a valid result)."
echo "results: $OUTDIR/resource-2h-summary.json ; guard: $GUARD"
[ "$present" -eq 0 ] || echo "WARNING: agent appeared during the run — result is NOT valid; re-run." >&2
