# Sprint 2 — Evaluation

Replay setup, detection results, and resource measurements. Status: ☐ Planned · ◐ In progress ·
☑ Done. **No detection/resource number is recorded without a linked raw-evidence file** under
`docs/sprint-2/evidence/`. No private network data (real MACs/IPs/hostnames) is committed.

Current status: **no dataset downloaded** (selection below awaits approval); **detection replay not
run yet**; the **2-hour live-traffic resource baseline is running** (§4). Datasets are downloaded
only after explicit approval.

---

## 1. Datasets (selection for approval) — ☐ HOLD, nothing downloaded
Metadata gathered 2026-11-02 from the official sources (no dataset files fetched). **Available disk:**
`/` (and `/home`) = 235 GB total, **214 GB free (5% used)** — ample for either dataset.
Per-file sizes/SHA-256 that are not published are confirmed with an HTTP `HEAD` / listing at the
moment of (approved) download, **before** pulling large files, and recorded here.

### IoT-23 (Stratosphere Laboratory, CTU)
- **Source:** `https://www.stratosphereips.org/datasets-iot23` · **Zenodo:** record 4743746
  (DOI `10.5281/zenodo.4743746`). **Licence: CC-BY-4.0** (confirmed via Zenodo API).
- **Reference:** Garcia, Parmisano, Erquiaga, *IoT-23: A labeled dataset…*, 2020.
- **Distribution (confirmed):** a single archive `iot_23_datasets_full.tar.gz` —
  **21,510,801,277 bytes (~20.0 GiB)**, `md5:7132e603f9750b8580b6cebdbcd43e9c`. It contains
  **20 malware + 3 benign** captures, each with a `.pcap`. Individual pcaps are **not** separately
  published on Zenodo (they live inside the archive); a per-scenario HTTP mirror exists on the
  Stratosphere server but its current index path returned 404 on 2026-11-02 (to re-locate).
- **Proposed selection** (small, clearly labelled; extracted from the archive, the rest discarded):
  `CTU-IoT-Malware-Capture-34-1` (Mirai), `-8-1` (Hakai), `-60-1` (Gafgyt), `-20-1` (Torii), and
  benign `CTU-Honeypot-Capture-7-1`. Per-capture pcap byte sizes + SHA-256: **to confirm after
  extraction** (not individually published).
- **Download size:** 20.0 GiB (archive). **Extracted size:** not published; fits comfortably in
  214 GB free. *(If pulling 20 GiB is undesirable, the alternative is the per-scenario Stratosphere
  mirror once its index URL is re-located — then only the selected pcaps are fetched.)*

### CICIoT2023 (Canadian Institute for Cybersecurity, UNB)
- **Source:** `https://www.unb.ca/cic/datasets/iotdataset-2023.html` → files under
  `http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/` (`PCAP/`, `CSV/`).
  **Licence:** CIC terms — free for research, **citation required**.
- **Reference / DOI:** Neto et al., *CICIoT2023…*, *Sensors* 23(13):5941, 2023 — `10.3390/s23135941`.
- **Attack classes (33 attacks / 7 classes):** DDoS (11), DoS (4), Recon (5), Web (6), Brute Force
  (1), Spoofing (2), Mirai (3); 105 IoT devices.
- **Proposed selection** (one small labelled PCAP per class for coverage, e.g. a Recon scan, a
  DoS/DDoS flood, a Mirai flood, a Spoofing capture, plus a `BenignTraffic` sample).
- **Download/extracted sizes + SHA-256:** the `PCAP/` directory is **not web-autoindexed** (the URL
  302-redirects to the CIC portal), so exact per-file sizes could not be retrieved now; they are
  captured via `HEAD` at approved download. The raw PCAP set is large (multi-GB per attack).

### On approval
No file is pulled until approved. On approval I first record each selected file's exact size (`HEAD`)
and SHA-256 (and extracted sizes), update this section, verify against the source, then replay.

---

## 2. Replay environment and method — ☐ Planned
- **Goal:** traffic must reach the monitored interface `eth1` (the SPAN/mirror port), exactly like
  live monitoring — not injected into the appliance's own stack.
- **Proposed method:** `tcpreplay` from a second host into a switch port that is mirrored to the
  port Suricata watches, so replayed packets appear on `eth1`. (Alternative, if no managed switch:
  replay onto the mirror source segment.) Final wiring recorded here once set up.
- To record per run: replay host + OS, `tcpreplay` version and exact command (incl. `--intf`,
  pps/`--mbps`, loop), switch mirror config, start/stop timestamps, the pcap(s) and their SHA-256,
  and the **ET Open rules date/version** in use.
- Detection is measured from **raw Suricata `alert` events (pre-dedup)** in `eve.json`, matched to
  each attack by **time window + addresses**; an alert merely appearing during replay does **not**
  count.

## 3. Detection results — ☐ Planned
Per-attack table (one row per labelled attack class), filled from raw eve evidence:

| Dataset | Attack class | Time window | Matched signature(s) (sid) | Detected? | Raw evidence |
|---|---|---|---|---|---|
| *(pending)* | | | | | |

- Benign-traffic alerts (false positives) recorded separately with sid + count + evidence path.
- ET Open has partial coverage by design: undetected attacks are recorded as-is, no full-coverage
  assumption.
- Raw eve slices and the matching script/output saved under `evidence/detection/`.

## 4. Resources — ◐ 2-hour LIVE-TRAFFIC BASELINE running (started 2026-11-02 ~13:37 UTC)
All existing services + `assas-suricata` + `assas-alerts` running. **Scope:** this is a
baseline under *live house traffic*, not proof of performance under attack or heavy load; the
attack-replay run (§2–3) will be measured separately once datasets are approved.

Method: `appliance/tools/resource_sampler.py 7200 10` (720 samples @10 s), reading `/proc/stat`
(total device CPU 0–100%), `/proc/meminfo` (`MemTotal−MemAvailable`), `/sys/class/net/eth1/statistics`
(throughput), and the eve `stats` `capture.kernel_packets`/`kernel_drops` deltas (drop rate). Rules
version: ET Open 2026-11-02 (53,305 sigs). Output: `evidence/resources/resource-2h.csv` (+
`resource-2h-summary.json` at completion).

**Important measurement caveat:** during this baseline the **Claude Code dev agent is co-resident on
the appliance (~2.4 GB RSS)** and inflates total-device memory; it is **not** part of the deployed
appliance. The appliance-only footprint is recorded separately in
`evidence/resources/appliance-footprint.txt`: **~1.49 GB total** (Suricata ~1.06 GB, display app
~0.20 GB, discovery ~0.13 GB, API ~0.08 GB, alerts ~0.02 GB) — comfortably under the 4 GB target.

| Metric | Target | Measured | Evidence |
|---|---|---|---|
| Total device CPU (0–100%) | avg ≤ 75% | *filled at completion* | `resource-2h-summary.json` |
| Memory — appliance services only | < 4 GB of 8 GB | **~1.49 GB** ✓ | `appliance-footprint.txt` |
| Memory — total device (incl. dev agent) | context only | *filled at completion* | `resource-2h.csv` |
| Traffic rate during test | record | first sample ~5.6 kbps (quiet) | `resource-2h.csv` |
| Suricata packet-drop rate | record | first sample 0 drops / 192k pkts | eve `stats`, `resource-2h.csv` |

First sample (13:37 UTC): CPU 32.3%, total mem 5813 MB (incl. dev agent), rx ~5.6 kbps, 0 drops.
Final averages/max and drop-rate are written to `resource-2h-summary.json` when the run ends
(~15:37 UTC) and committed then.
