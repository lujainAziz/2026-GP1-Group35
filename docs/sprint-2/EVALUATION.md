# Sprint 2 — Evaluation

Replay setup, detection results, and resource measurements. Status: ☐ Planned · ◐ In progress ·
☑ Done. **No detection/resource number is recorded without a linked raw-evidence file** under
`docs/sprint-2/evidence/`. No private network data (real MACs/IPs/hostnames) is committed.

Current status: **☐ Planned — no dataset downloaded, no replay run yet.** Datasets are downloaded
only after explicit approval.

---

## 1. Datasets (provenance) — ☐ pending download approval
Official source pages, references, and licences recorded now (accessed 2026-11-02); the exact
selected files, sizes, and **SHA-256** are filled in **after approved download** and verified
against the source before any replay.

### CICIoT2023
| Field | Value |
|---|---|
| Official source | Canadian Institute for Cybersecurity (CIC), UNB — `https://www.unb.ca/cic/datasets/iotdataset-2023.html` |
| Actual download URL | *to record at download (from the CIC page)* |
| Reference / DOI | Neto et al., "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment," *Sensors* 23(13):5941, 2023 — DOI `10.3390/s23135941` (confirm at access) |
| Licence | CIC terms: free for research with citation required (confirm on the page at download) |
| Selected files / parts | *to record* (prefer labelled attack PCAPs over merged CSVs) |
| Size / SHA-256 | *to record after download* |

### IoT-23
| Field | Value |
|---|---|
| Official source | Stratosphere Laboratory, CTU — `https://www.stratosphereips.org/datasets-iot23` |
| Actual download URL | *to record at download* (Zenodo mirror) |
| Reference / DOI | Garcia, Parmisano, Erquiaga, "IoT-23: A labeled dataset with malicious and benign IoT network traffic," 2020 — Zenodo DOI `10.5281/zenodo.4743746` (confirm at access) |
| Licence | per the Zenodo record (confirm at access) |
| Selected files / parts | *to record* (labelled malicious + benign captures with PCAPs) |
| Size / SHA-256 | *to record after download* |

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

## 4. Resources (continuous 2-hour run) — ☐ Planned
All existing services + `assas-suricata` (+ `assas-alerts`) running.

| Metric | Target | Measured | Evidence |
|---|---|---|---|
| Total device CPU (0–100%) | avg ≤ 75% | *pending* | `evidence/resources/cpu.*` |
| Memory | < 4 GB of 8 GB | *pending* | `evidence/resources/mem.*` |
| Traffic rate during test | record | *pending* | `evidence/resources/traffic.*` |
| Suricata packet-drop rate | record | *pending* | eve `stats.capture.kernel_drops` vs `kernel_packets` |

Method and sampling commands (e.g. `pidstat`/`/proc`, eve `stats` deltas) recorded here with the
run's start/stop timestamps and rules version.
