#!/usr/bin/env bash
# IoT-23 batch runner (Tasks B1/B2): runs the steps of IOT23_OFFLINE_TEST.md for every
# scenario in iot23_scenarios.txt, one scenario at a time, each in its own folder with
# its own test database. Never touches the real database or the running services.
#
#   iot23_batch.sh [--plan] [--only SCENARIO]...
#
#   --plan   show the pcap(s) and host IP(s) chosen per scenario, run nothing
#   --only   run just these scenarios (repeatable)
#
# Resumable: a scenario with OUT/<scenario>/DONE is skipped; an unfinished one is
# redone from scratch. Stops cleanly when free disk on /home (IOT23_DISK_PATH) drops below
# IOT23_MIN_FREE_GB (also while Suricata runs). Writes OUT/results/summary.csv.
#
# Environment (defaults in brackets):
#   IOT23_DATA          IoTScenarios folder [/home/assas/dataset-eval/iot23/opt/Malware-Project/BigDataset/IoTScenarios]
#   IOT23_OUT           output folder [/home/assas/iot23-batch]
#   IOT23_TABLE         scenario table [iot23_scenarios.txt next to this script]
#   IOT23_MIN_FREE_GB   stop below this much free space [5]
#   IOT23_DISK_PATH     file system to watch [/home]
#   IOT23_EVE_MODE      after ingest: alerts (keep alert lines gzipped, delete eve.json),
#                       gzip (gzip the whole eve.json) or delete [alerts]
#   IOT23_SHA256        1 records each pcap's sha256 [1]
#   IOT23_SUDO          prefix for suricata when the rules can't be read as assas, e.g. "sudo -n" []
#   IOT23_SURICATA_CONF [/etc/suricata/assas.yaml]
#   ASSAS_REAL_DB       schema source, opened read-only [/home/assas/assas/assas.db]
#   PYTHON              [python3]
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DATA=${IOT23_DATA:-/home/assas/dataset-eval/iot23/opt/Malware-Project/BigDataset/IoTScenarios}
OUT=${IOT23_OUT:-/home/assas/iot23-batch}
TABLE=${IOT23_TABLE:-$HERE/iot23_scenarios.txt}
MIN_FREE_GB=${IOT23_MIN_FREE_GB:-5}
EVE_MODE=${IOT23_EVE_MODE:-alerts}
DO_SHA=${IOT23_SHA256:-1}
SUDO=${IOT23_SUDO:-}
read -r -a SUDO_CMD <<<"$SUDO"
SURI_CONF=${IOT23_SURICATA_CONF:-/etc/suricata/assas.yaml}
REAL_DB=${ASSAS_REAL_DB:-/home/assas/assas/assas.db}
PY=${PYTHON:-python3}
DISK_PATH=${IOT23_DISK_PATH:-/home}
HELPER=$HERE/iot23_batch.py

PLAN=0
ONLY=()
while [ $# -gt 0 ]; do
    case $1 in
        --plan) PLAN=1 ;;
        --only) shift; ONLY+=("${1:?--only needs a scenario}") ;;
        -h|--help) sed -n '2,/^set -u/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

case $EVE_MODE in alerts|gzip|delete) ;; *) echo "IOT23_EVE_MODE must be alerts, gzip or delete" >&2; exit 2 ;; esac
[ -d "$DATA" ] || { echo "dataset folder not found: $DATA" >&2; exit 2; }
[ -f "$REAL_DB" ] || { echo "schema source not found: $REAL_DB" >&2; exit 2; }
case $OUT in /*) ;; *) echo "IOT23_OUT must be an absolute path" >&2; exit 2 ;; esac

SURI_PID=
CUR_DIR=
on_signal() {
    if [ -n "$SURI_PID" ]; then
        kill -TERM "$SURI_PID" 2>/dev/null || { [ -n "$SUDO" ] && "${SUDO_CMD[@]}" kill -TERM "$SURI_PID"; }
        wait "$SURI_PID" 2>/dev/null
    fi
    [ -n "$CUR_DIR" ] && echo "interrupted; $CUR_DIR is unfinished and will be redone" >&2
    exit 130
}
trap on_signal INT TERM

free_kb() { df -Pk "$DISK_PATH" | awk 'NR == 2 { print $4 }'; }
disk_ok() {
    local kb
    kb=$(free_kb)
    case $kb in ''|*[!0-9]*) echo "cannot read free space on $DISK_PATH" >&2; return 1 ;; esac
    [ "$kb" -ge $((MIN_FREE_GB * 1024 * 1024)) ]
}

wanted() {
    [ ${#ONLY[@]} -eq 0 ] && return 0
    local s
    for s in "${ONLY[@]}"; do [ "$s" = "$1" ] && return 0; done
    return 1
}

# The host's source MAC: tcpdump, then tshark, then the Python reader.
find_mac() { # pcap ip
    local mac=
    if command -v tcpdump >/dev/null 2>&1; then
        mac=$(tcpdump -nne -r "$1" -c 50 "src host $2" 2>/dev/null | awk '{ print $2 }' |
              sort | uniq -c | sort -rn | awk 'NR == 1 { print $2 }')
    elif command -v tshark >/dev/null 2>&1; then
        mac=$({ tshark -r "$1" -Y "ip.src == $2" -T fields -e eth.src 2>/dev/null || true; } |
              head -n 50 | sort | uniq -c | sort -rn | awk 'NR == 1 { print $2 }')
    fi
    mac=$(printf '%s' "$mac" | tr 'A-F' 'a-f')
    if ! printf '%s' "$mac" | grep -Eq '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'; then
        mac=$("$PY" "$HELPER" mac --pcap "$1" --ip "$2") || return 1
    fi
    printf '%s\n' "$mac"
}

# Addresses the ingester never links (device's own IPs and default gateways).
local_addrs() {
    ip -o addr show 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1
    ip route show default 2>/dev/null | awk '{ print $3 }'
}

# Suricata in the background so free disk can be watched. 99 = stopped for disk.
run_suricata() { # pcap rundir log
    local cmd=(nice -n 10) rc
    command -v ionice >/dev/null 2>&1 && cmd+=(ionice -c 3)
    [ -n "$SUDO" ] && cmd+=("${SUDO_CMD[@]}")
    cmd+=(suricata -c "$SURI_CONF" -r "$1" -l "$2" -k none --set unix-command.enabled=no)
    echo "+ ${cmd[*]}" >>"$3"
    (cd "$2" && exec "${cmd[@]}") >>"$3" 2>&1 &
    SURI_PID=$!
    while kill -0 "$SURI_PID" 2>/dev/null; do
        if ! disk_ok; then
            kill -TERM "$SURI_PID" 2>/dev/null || { [ -n "$SUDO" ] && "${SUDO_CMD[@]}" kill -TERM "$SURI_PID"; }
            wait "$SURI_PID" 2>/dev/null
            SURI_PID=
            return 99
        fi
        sleep 5
    done
    wait "$SURI_PID"
    rc=$?
    SURI_PID=
    [ -n "$SUDO" ] && "${SUDO_CMD[@]}" chown -R "$(id -u):$(id -g)" "$2"
    return $rc
}

# Scenario state shared with write_result.
S_KIND= S_SCEN= S_LABEL= S_DIR=
S_PCAPS=() S_IPS=() S_MACS=() S_EVES=()
S_SURI_SECS=0 S_START=0

write_result() { # status
    local args=(result --out "$S_DIR/result.json" --scenario "$S_SCEN" --kind "$S_KIND"
                --label "$S_LABEL" --status "$1" --db "$S_DIR/test.db"
                --suricata-seconds "$S_SURI_SECS" --run-seconds $((SECONDS - S_START))) x
    for x in "${S_PCAPS[@]}"; do args+=(--pcap "$x"); done
    for x in "${S_IPS[@]}"; do args+=(--host-ip "$x"); done
    for x in "${S_MACS[@]}"; do args+=(--mac "$x"); done
    for x in "${S_EVES[@]}"; do args+=(--eve "$x"); done
    "$PY" "$HELPER" "${args[@]}" >>"$S_DIR/run.log" 2>&1
}

say() { echo "[$S_SCEN] $*" | tee -a "$S_DIR/run.log"; }
stop() { say "status: $1"; write_result "$1"; return 1; }

# Host IP(s) of the selected pcaps: the table's, else one per file name.
host_ips_for() { # table_ips -> fills S_IPS, returns 1 if a pcap has no IP
    local p ip missing=0
    S_IPS=()
    if [ "$1" != "-" ]; then
        IFS=, read -r -a S_IPS <<<"$1"
        return 0
    fi
    for p in "${S_PCAPS[@]}"; do
        if ip=$("$PY" "$HELPER" ip "$p"); then
            case " ${S_IPS[*]} " in *" $ip "*) ;; *) S_IPS+=("$ip") ;; esac
        else
            echo "no IP in file name: $p"
            missing=1
        fi
    done
    return $missing
}

plan_scenario() { # kind scen label table_ips
    local p
    S_SCEN=$2
    echo "== $2 ($1, $3)$( [ -e "$OUT/$2/DONE" ] && echo '  [done]')"
    if ! mapfile -t S_PCAPS < <("$PY" "$HELPER" select --kind "$1" "$DATA/$2" 2>/dev/null) ||
            [ ${#S_PCAPS[@]} -eq 0 ]; then
        echo "   no pcap found in $DATA/$2"
        return
    fi
    for p in "${S_PCAPS[@]}"; do
        echo "   pcap: ${p#"$DATA"/}  ($(du -h "$p" | cut -f1))"
    done
    if host_ips_for "$4" | sed 's/^/   /'; then
        host_ips_for "$4" >/dev/null
        echo "   host IP(s): ${S_IPS[*]}"
    else
        echo "   host IP missing: add it to the table. Most frequent LAN sources:"
        for p in "${S_PCAPS[@]}"; do
            "$PY" "$HELPER" ip "$p" >/dev/null || "$PY" "$HELPER" hint --pcap "$p"
        done
    fi
}

run_scenario() { # kind scen label table_ips
    local p ip mac i rc t0 devs=() conflicts
    S_KIND=$1 S_SCEN=$2 S_LABEL=$3 S_DIR=$OUT/$2
    S_PCAPS=() S_IPS=() S_MACS=() S_EVES=() S_SURI_SECS=0 S_START=$SECONDS

    if [ -e "$S_DIR/DONE" ]; then
        echo "[$S_SCEN] done earlier, skipped"
        return 0
    fi
    disk_ok || return 3
    rm -rf -- "$S_DIR"
    mkdir -p "$S_DIR"
    CUR_DIR=$S_DIR
    say "start $(date -Is), free on $DISK_PATH: $(( $(free_kb) / 1024 / 1024 )) GB"

    mapfile -t S_PCAPS < <("$PY" "$HELPER" select --kind "$S_KIND" "$DATA/$S_SCEN" 2>>"$S_DIR/run.log")
    [ ${#S_PCAPS[@]} -gt 0 ] || { stop no_pcap; return; }
    for p in "${S_PCAPS[@]}"; do say "pcap: $p ($(stat -c %s "$p") bytes)"; done

    if ! host_ips_for "$4" >>"$S_DIR/run.log"; then
        say "a pcap has no IP in its name; set host_ip in $TABLE (see --plan for a hint)"
        stop need_ip
        return
    fi
    conflicts=$(local_addrs | grep -Fxf <(printf '%s\n' "${S_IPS[@]}") || true)
    if [ -n "$conflicts" ]; then
        say "host IP is this device's own address or gateway, so it would never link: $conflicts"
        stop ip_conflict
        return
    fi

    for ip in "${S_IPS[@]}"; do
        mac=
        for p in "${S_PCAPS[@]}"; do
            mac=$(find_mac "$p" "$ip" 2>>"$S_DIR/run.log") && break
        done
        [ -n "$mac" ] || { say "no frames from $ip found"; stop no_mac; return; }
        say "host: $ip $mac"
        S_MACS+=("$mac")
        devs+=(--device "$mac,$ip,IoT-23 ${S_SCEN#CTU-} ($S_LABEL)")
    done
    if ! "$PY" "$HERE/iot23_seed_devices.py" --db "$S_DIR/test.db" --schema-from "$REAL_DB" \
            "${devs[@]}" >>"$S_DIR/run.log" 2>&1; then
        stop seed_failed
        return
    fi

    i=0
    for p in "${S_PCAPS[@]}"; do
        i=$((i + 1))
        mkdir -p "$S_DIR/run$i"
        [ "$DO_SHA" = 1 ] && (cd "$(dirname "$p")" && sha256sum "$(basename "$p")") >>"$S_DIR/pcap.sha256"
        say "suricata run$i: $(basename "$p")"
        t0=$SECONDS
        run_suricata "$p" "$S_DIR/run$i" "$S_DIR/run$i/suricata.out"
        rc=$?
        S_SURI_SECS=$((S_SURI_SECS + SECONDS - t0))
        if [ $rc -eq 99 ]; then
            say "free disk below $MIN_FREE_GB GB; stopping"
            stop stopped_disk
            return 3
        fi
        [ $rc -eq 0 ] && [ -f "$S_DIR/run$i/eve.json" ] || { say "suricata exit $rc"; stop suricata_failed; return; }
        S_EVES+=("$S_DIR/run$i/eve.json")
        if ! "$PY" "$HERE/iot23_ingest_once.py" --db "$S_DIR/test.db" --eve "$S_DIR/run$i/eve.json" \
                2>&1 | tee -a "$S_DIR/run.log" | sed "s/^/[$S_SCEN] /"; then
            stop ingest_failed
            return
        fi
    done

    write_result done || { say "could not write result.json"; return 1; }
    for p in "${S_EVES[@]}"; do
        case $EVE_MODE in
            alerts) grep -F '"event_type":"alert"' "$p" | gzip >"${p%.json}-alerts.json.gz"; rm -f -- "$p" ;;
            gzip) gzip -f -- "$p" ;;
            delete) rm -f -- "$p" ;;
        esac
        [ -f "$(dirname "$p")/fast.log" ] && gzip -f -- "$(dirname "$p")/fast.log"
    done
    date -Is >"$S_DIR/DONE"
    CUR_DIR=
    say "done in $((SECONDS - S_START)) s"
}

mkdir -p "$OUT"
if [ $PLAN -eq 0 ] && command -v flock >/dev/null 2>&1; then
    exec 9>"$OUT/.lock"
    flock -n 9 || { echo "another iot23_batch.sh is running on $OUT" >&2; exit 2; }
fi
ROWS=$("$PY" "$HELPER" table "$TABLE") || exit 2

if [ $PLAN -eq 1 ]; then
    while IFS=$'\t' read -r kind scen label ips; do
        wanted "$scen" && plan_scenario "$kind" "$scen" "$label" "$ips"
    done <<<"$ROWS"
    exit 0
fi

{
    echo "== $(date -Is)"
    suricata -V 2>&1 | head -n 1
    ls -l --time-style=long-iso /var/lib/suricata/rules/suricata.rules 2>&1
    echo "config: $SURI_CONF  eve mode: $EVE_MODE  min free: $MIN_FREE_GB GB"
} >>"$OUT/run-info.txt"

status=0
while IFS=$'\t' read -r kind scen label ips; do
    wanted "$scen" || continue
    run_scenario "$kind" "$scen" "$label" "$ips" </dev/null
    rc=$?
    if [ $rc -eq 3 ]; then
        echo "free disk on $DISK_PATH below $MIN_FREE_GB GB; stopped before/at $scen" >&2
        status=3
        break
    fi
    [ $rc -ne 0 ] && status=1
done <<<"$ROWS"

"$PY" "$HELPER" summary --table "$TABLE" --out-dir "$OUT"
exit $status
