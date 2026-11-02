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
Per-file sizes are taken from the publisher autoindex where shown; SHA-256 is computed only after
download.

### IoT-23 (Stratosphere Laboratory, CTU)
- **Source:** `https://www.stratosphereips.org/datasets-iot23` · Zenodo record 4743746
  (DOI `10.5281/zenodo.4743746`). **Licence: CC-BY-4.0** (confirmed via Zenodo API).
  **Reference:** Garcia, Parmisano, Erquiaga, *IoT-23…*, 2020.
- **Official per-capture downloads (preferred — avoids the 20 GiB archive):** the publisher mirror
  serves each scenario at
  `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/<capture>/` with a
  directly downloadable `.pcap` (size shown in the autoindex), a publisher `.capinfos` (capture
  metadata), and a README stating the label. Confirmed 2026-11-02.
- **Proposed selection** (small, labelled; filenames are the dataset's own public artifact names):

  | Capture | Label (per dataset docs) | PCAP file | Size (autoindex) |
  |---|---|---|---|
  | CTU-IoT-Malware-Capture-34-1 | Mirai | `2018-12-21-15-50-14-…195.pcap` | **120 MB** |
  | CTU-IoT-Malware-Capture-8-1 | Hakai | `2018-07-31-15-15-09-…113.pcap` | **2.0 MB** |
  | CTU-IoT-Malware-Capture-20-1 | Torii | `2018-10-02-13-12-30-…103.pcap` | **3.9 MB** |
  | CTU-Honeypot-Capture-7-1 | benign (Somfy device) | under `Somfy-0X/` subfolders | TBD at approval |

  Rejected `CTU-IoT-Malware-Capture-60-1` — its pcap is **21 GB**. The three malware captures total
  ≈ **126 MB** (trivially within 214 GB free).
- **Full archive — only if per-capture proves insufficient:** `iot_23_datasets_full.tar.gz` =
  21,510,801,277 B (~20.0 GiB), **publisher `md5:7132e603f9750b8580b6cebdbcd43e9c`**. Use of the
  archive requires separate approval and an expected extracted size (not published; estimated from
  the `.capinfos` metadata beforehand).
- **Checksums:** record publisher-provided values where available (the archive md5 above; per-capture
  `.capinfos` is capture metadata, not a hash). **SHA-256 is computed after download, never before.**

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
  302-redirects to the CIC portal), so exact per-file sizes are not available without access; an
  HTTP `HEAD` at download captures them. The raw PCAP set is large (multi-GB per attack).

### Download procedure
Each selected file's exact size (`HEAD`) and extracted size are recorded first and this section is
updated and verified against the source; SHA-256 is computed after download; replay follows.

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

**Acceptance metrics are total-device CPU and total-device memory** (the resource targets apply to
the whole device). Both are measured and judged as-is; the total memory figure is **not** adjusted
by excluding any process.

**Measurement caveat (does not change the acceptance figure):** during this baseline a development
agent (Claude Code) is co-resident on the appliance (~2.4 GB RSS) and is included in total-device
memory. It is not part of the deployed appliance. Its presence means the total-memory result here
may **overstate** the appliance's own usage; if the total-memory target is not met under this
baseline, a **separate representative run without the development agent** is required before judging
the target (procedure below). The appliance-service footprint is reported separately for context
(not a substitute for the total-device figure).

Primary (acceptance):

| Metric | Target | Measured | Evidence |
|---|---|---|---|
| Total-device CPU (0–100%) | avg ≤ 75% | *filled at completion* | `resource-2h-summary.json` |
| Total-device memory | < 4 GB of 8 GB | *filled at completion (incl. co-resident dev agent)* | `resource-2h.csv`, `-summary.json` |
| Traffic rate during test | record | first sample ~5.6 kbps (quiet) | `resource-2h.csv` |
| Suricata packet-drop rate | record | first sample 0 drops / 192k pkts | eve `stats`, `resource-2h.csv` |

Secondary (context only, not an acceptance substitute):

| Metric | Measured | Evidence |
|---|---|---|
| Appliance-service memory (RSS sum) | ~1.49 GB (Suricata ~1.06, display ~0.20, discovery ~0.13, API ~0.08, alerts ~0.02) | `appliance-footprint.txt` |

First sample (13:37 UTC): total-device CPU 32.3%, total-device mem 5813 MB (incl. dev agent),
rx ~5.6 kbps, 0 drops. Final averages/max and drop-rate are written to `resource-2h-summary.json`
when the run ends (~15:37 UTC) and committed with a completion check (duration, sampling gaps,
service continuity).

**Representative run without the development agent (if needed):** stop the Claude Code agent, re-run
`appliance/tools/resource_sampler.py 7200 10` with only the appliance services active, and record
total-device memory from that run as the acceptance figure.
