#!/usr/bin/env python3
"""Continuous appliance resource sampler for the Sprint 2 evaluation (PBI-13/14).

Records, with all services running, the metrics PBI-13 asks for:
  - total device CPU on a 0-100% scale (target: average <= 75%),
  - memory used of total (target: < 4 GB of 8 GB),
  - traffic rate on the capture interface,
  - Suricata packet-drop rate (from eve `stats` capture.kernel_packets/kernel_drops).

Reads only /proc, /sys and the world-readable eve.json -> no root needed.
Writes an incremental CSV plus a summary JSON so partial data survives a stop.

Usage: resource_sampler.py [duration_seconds] [interval_seconds]
Env: ASSAS_EVE_PATH, ASSAS_CAPTURE_IFACE, ASSAS_RES_OUTDIR.
"""
import glob
import json
import os
import sys
import time
from datetime import datetime, timezone

DURATION = 7200       # 2 hours (overridden by argv in main())
INTERVAL = 10.0
IFACE = os.getenv("ASSAS_CAPTURE_IFACE", "eth1")
EVE = os.getenv("ASSAS_EVE_PATH", "/var/log/suricata/eve.json")
OUTDIR = os.getenv("ASSAS_RES_OUTDIR", "/home/assas/assas/docs/sprint-2/evidence/resources")
CSV = os.path.join(OUTDIR, "resource-2h.csv")
SUMMARY = os.path.join(OUTDIR, "resource-2h-summary.json")


def read_cpu():
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
    total = sum(vals)
    return idle, total


def read_mem():
    """Used/total memory in MiB (binary): /proc/meminfo's 'kB' are KiB.

    'used' = MemTotal - MemAvailable (the kernel's estimate of allocatable
    memory without swapping): anonymous pages + shmem (incl. graphics buffers)
    + unreclaimable kernel memory; reclaimable page cache is NOT counted.
    NOTE the acceptance threshold below (4096) is therefore 4 GiB = 4.295 GB
    decimal; against 4 GB decimal the bound would be 3815 MiB.
    """
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            info[k] = int(v.strip().split()[0])  # KiB
    total = info["MemTotal"]
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    return (total - avail) // 1024, total // 1024  # MiB used, MiB total


def read_net(iface):
    base = f"/sys/class/net/{iface}/statistics"
    try:
        def r(n):
            with open(f"{base}/{n}") as f:
                return int(f.read())
        return r("rx_bytes"), r("tx_bytes"), r("rx_packets"), r("tx_packets")
    except OSError:
        return None


def read_suri_stats():
    """Last eve `stats` event's cumulative capture counters (pkts, drops)."""
    path = EVE
    if not os.path.exists(path):
        rotated = sorted(glob.glob(glob.escape(EVE) + "-*"))
        if not rotated:
            return None
        path = rotated[-1]
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 131072))
            tail = f.read().split(b"\n")
    except OSError:
        return None
    for raw in reversed(tail):
        raw = raw.strip()
        if not raw or b'"stats"' not in raw:
            continue
        try:
            o = json.loads(raw)
        except ValueError:
            continue
        cap = (o.get("stats") or {}).get("capture") or {}
        if "kernel_packets" in cap:
            return int(cap.get("kernel_packets", 0)), int(cap.get("kernel_drops", 0))
    return None


def _is_suricata_comm(comm):
    """True for Suricata's process name as the kernel reports it.

    /proc/<pid>/comm for Suricata 7 is "Suricata-Main" (not "suricata") — the
    clean 2h run's pid_start/pid_end were null for exactly this reason, which
    alone invalidated an otherwise clean drop measurement.
    """
    return comm in ("suricata", "Suricata-Main")


def read_suri_pid():
    """PID of the running suricata process (to detect a restart during the run)."""
    for p in glob.glob("/proc/[0-9]*/comm"):
        try:
            with open(p) as f:
                if _is_suricata_comm(f.read().strip()):
                    return int(p.rsplit("/", 2)[1])
        except OSError:
            continue
    return None


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main():
    # argv parsed here (not at import) so the module stays import-safe for tests.
    global DURATION, INTERVAL
    if len(sys.argv) > 1:
        DURATION = int(sys.argv[1])
    if len(sys.argv) > 2:
        INTERVAL = float(sys.argv[2])
    os.makedirs(OUTDIR, exist_ok=True)
    start = time.time()
    idle0, tot0 = read_cpu()
    net0 = read_net(IFACE)
    suri_first = read_suri_stats()
    suri_pid_start = read_suri_pid()

    # Reset-aware Suricata counters: kernel_packets/kernel_drops are cumulative
    # and reset to 0 when suricata restarts, so a simple last-first can go
    # negative / under-count. We sum per-sample deltas and start a fresh segment
    # whenever a counter decreases (a restart). Missing samples (stats not yet
    # written) are recorded as blank, never 0, so "no measurement" != "zero".
    suri_pkts_acc = suri_drops_acc = 0
    suri_prev = suri_first
    suri_resets = suri_missing = suri_valid_deltas = 0
    suri_pids_seen = set()
    suri_pid_prev = suri_pid_start
    suri_pid_missing = 0
    suri_pid_changes = 0
    if suri_pid_start is not None:
        suri_pids_seen.add(suri_pid_start)

    cpu_samples, mem_used_samples, rxbps_samples, txbps_samples = [], [], [], []
    new = not os.path.exists(CSV)
    with open(CSV, "a", buffering=1) as csv:
        if new:
            csv.write("utc,cpu_pct,mem_used_mib,mem_total_mib,rx_bps,tx_bps,rx_pps,tx_pps,"
                      "suri_kernel_packets,suri_kernel_drops,suri_pid\n")
        last_net = net0
        last_idle, last_tot = idle0, tot0
        last_t = start
        while time.time() - start < DURATION:
            time.sleep(INTERVAL)
            t = time.time()
            idle1, tot1 = read_cpu()
            dt_idle, dt_tot = idle1 - last_idle, tot1 - last_tot
            cpu_pct = round(100.0 * (1 - dt_idle / dt_tot), 1) if dt_tot > 0 else 0.0
            last_idle, last_tot = idle1, tot1

            mem_used, mem_total = read_mem()
            net1 = read_net(IFACE)
            span = max(1e-6, t - last_t)
            if net1 and last_net:
                rx_bps = int((net1[0] - last_net[0]) * 8 / span)
                tx_bps = int((net1[1] - last_net[1]) * 8 / span)
                rx_pps = int((net1[2] - last_net[2]) / span)
                tx_pps = int((net1[3] - last_net[3]) / span)
            else:
                rx_bps = tx_bps = rx_pps = tx_pps = 0
            last_net = net1 or last_net
            last_t = t

            suri = read_suri_stats()
            if suri is None:
                suri_missing += 1
                suri_pkts_str = suri_drops_str = ""  # blank: measurement missing, not 0
            else:
                suri_pkts_str, suri_drops_str = str(suri[0]), str(suri[1])
                if suri_prev is not None:
                    dp, dd = suri[0] - suri_prev[0], suri[1] - suri_prev[1]
                    if dp >= 0 and dd >= 0:
                        suri_pkts_acc += dp
                        suri_drops_acc += dd
                        suri_valid_deltas += 1
                    else:
                        suri_resets += 1  # counter went backwards -> suricata restarted
                suri_prev = suri

            # Suricata process identity sampled EVERY interval (not only at the
            # start/end): a mid-run restart is visible even if a new process
            # ends on the same counters.
            pid_now = read_suri_pid()
            if pid_now is None:
                suri_pid_missing += 1
            else:
                suri_pids_seen.add(pid_now)
                if suri_pid_prev is not None and pid_now != suri_pid_prev:
                    suri_pid_changes += 1
                suri_pid_prev = pid_now

            csv.write(f"{now_iso()},{cpu_pct},{mem_used},{mem_total},{rx_bps},{tx_bps},"
                      f"{rx_pps},{tx_pps},{suri_pkts_str},{suri_drops_str},"
                      f"{pid_now if pid_now is not None else ''}\n")
            cpu_samples.append(cpu_pct)
            mem_used_samples.append(mem_used)
            rxbps_samples.append(rx_bps)
            txbps_samples.append(tx_bps)

    # Fold in the final sample's delta, then use the reset-aware accumulators.
    suri_last = read_suri_stats()
    if suri_last is not None and suri_prev is not None:
        dp, dd = suri_last[0] - suri_prev[0], suri_last[1] - suri_prev[1]
        if dp >= 0 and dd >= 0:
            suri_pkts_acc += dp
            suri_drops_acc += dd
            suri_valid_deltas += 1
        else:
            suri_resets += 1
    suri_pid_end = read_suri_pid()
    # d_pkts/d_drops are the sum of valid per-segment deltas (restart-safe).
    have_suri = suri_valid_deltas > 0
    d_pkts = suri_pkts_acc if have_suri else None
    d_drops = suri_drops_acc if have_suri else None

    def avg(xs):
        return round(sum(xs) / len(xs), 2) if xs else None

    summary = {
        "started": now_iso_from(start),
        "ended": now_iso(),
        "duration_seconds": int(time.time() - start),
        "interval_seconds": INTERVAL,
        "samples": len(cpu_samples),
        "cpu_pct_avg": avg(cpu_samples),
        "cpu_pct_max": max(cpu_samples) if cpu_samples else None,
        "cpu_target_avg_le_75": (avg(cpu_samples) or 0) <= 75,
        "mem_used_mb_avg": avg(mem_used_samples),
        "mem_used_mb_max": max(mem_used_samples) if mem_used_samples else None,
        "mem_total_mb": read_mem()[1],
        "mem_target_under_4gb": (max(mem_used_samples) if mem_used_samples else 0) < 4096,
        "rx_bps_avg": avg(rxbps_samples),
        "tx_bps_avg": avg(txbps_samples),
        "suricata_pkts_during": d_pkts,
        "suricata_drops_during": d_drops,
        "suricata_drop_rate_pct": (round(100.0 * d_drops / d_pkts, 4)
                                   if d_pkts and d_pkts > 0 else None),
        # Continuity / validity of the Suricata drop measurement.
        "suricata_resets_detected": suri_resets,
        "suricata_missing_samples": suri_missing,
        "suricata_valid_delta_samples": suri_valid_deltas,
        "suricata_pid_start": suri_pid_start,
        "suricata_pid_end": suri_pid_end,
        "suricata_pid_changed": (suri_pid_start != suri_pid_end),
        # Per-interval process-identity sampling (not just start/end).
        "suricata_pids_observed": sorted(suri_pids_seen),
        "suricata_pid_changes": suri_pid_changes,
        "suricata_pid_missing_samples": suri_pid_missing,
        # Units are binary: mem values are MiB; the 4096 threshold = 4 GiB.
        "mem_units": "MiB (threshold 4096 MiB = 4 GiB; 4 GB decimal = 3815 MiB)",
        # The drop rate is only an unqualified pass if suricata ran continuously
        # (same PID in every sample) and every interval had a stats sample.
        "suricata_drop_measurement_valid": (
            have_suri and suri_resets == 0 and suri_missing == 0
            and suri_pid_start is not None and suri_pid_start == suri_pid_end
            and suri_pid_changes == 0 and suri_pid_missing == 0
        ),
    }
    with open(SUMMARY, "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


def now_iso_from(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


if __name__ == "__main__":
    main()
