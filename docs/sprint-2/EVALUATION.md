# Sprint 2 — Evaluation

This document covers two evaluations: **detection accuracy** on a labelled attack dataset
(IoT-23, offline), and
**resource usage** of the appliance under load. Status markers: ☐ Planned · ◐ In progress ·
☑ Done. **No resource figure is recorded without a linked raw-evidence file** under
`docs/sprint-2/evidence/`. The detection figures come from the offline IoT-23 run
(`appliance/tools/IOT23_OFFLINE_TEST.md`) and are reported in Chapter 5 of the project report. No private network data (real addresses, MAC addresses or hostnames) is
committed.

**Detection evaluation — completed offline on IoT-23 (23-24 November 2026).** 20 malware captures
and 3 benign captures from IoT-23 were read offline by Suricata on the appliance (`suricata -r`)
with the device configuration and rule set unchanged, then processed by the real alert pipeline
into a separate test database. No traffic was replayed and no malware was executed (procedure:
`appliance/tools/IOT23_OFFLINE_TEST.md`). Assas raised alerts on the infected device in **16 of 20**
malware captures (4 Strong, 12 Indirect, 0 Weak, 4 Not detected). There was no alert on any device
in the benign captures (one low-severity protocol event in the Philips Hue capture was not
associated with a device). Precision and recall were not computed, and CICIoT2023 was not tested in Release 1. Results
are in section 3; full results are in Chapter 5 of the project report.

**Resource-usage evaluation — three 2-hour runs, taken with only the appliance services
running.** On 5 November 2026 the CPU target was met and the memory target was not (maximum
4.37 GiB). On 17 November 2026 two runs, at about 1.2 Mbps and 10.5 Mbps of traffic, met the CPU
and memory targets, with no packets dropped and a validated drop measurement. Details in section 4.

---

## 1. Datasets — ☑ IoT-23 used (offline evaluation); CICIoT2023 not tested in Release 1
> **Record of the original plan (not used):** the selection and download procedure below were
> written for the replay method in §2, which was not used. The evaluation read 20 malware and 3
> benign IoT-23 captures offline on the appliance (`appliance/tools/IOT23_OFFLINE_TEST.md`);
> results in §3.

Metadata gathered 2026-11-02 from the official sources. SHA-256 is
computed only after download; publisher checksums are recorded where available.

**Download target is the replay host, not the Pi.** Datasets are downloaded onto the dedicated
replay host (§2); the appliance only ever sees the mirrored replayed traffic on `eth1`. Disk is
therefore sized on the replay host (recorded in §2 once finalized), not on the Pi.

**First approval covers IoT-23 only; CICIoT2023 remains on hold.**

### IoT-23 (Stratosphere Laboratory, CTU)
- **Source:** `https://www.stratosphereips.org/datasets-iot23` · Zenodo record 4743746
  (DOI `10.5281/zenodo.4743746`). **Licence: CC-BY-4.0** (confirmed via Zenodo API).
  **Reference:** Garcia, Parmisano, Erquiaga, *IoT-23…*, 2020.
- **Official per-capture downloads (preferred — avoids the 20 GiB archive):** the publisher mirror
  serves each scenario at
  `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/<capture>/` with a
  directly downloadable `.pcap` (size shown in the autoindex), a publisher `.capinfos` (capture
  metadata), and a README stating the label. Confirmed 2026-11-02.
- **Proposed selection** (small, labelled; exact direct URLs; filenames are the dataset's own public
  artifact names). Base = `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`:

  | Capture | Label | Direct PCAP URL (under base) | Size |
  |---|---|---|---|
  | Malware-34-1 | Mirai | `CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap` | **120 MB** |
  | Malware-8-1 | Hakai | `CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap` | **2.0 MB** |
  | Malware-20-1 | Torii | `CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap` | **3.9 MB** |
  | Honeypot-7-1 | benign (Somfy) | `CTU-Honeypot-Capture-7-1/Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap` | **2.0 MB** |

  Total ≈ **128 MB** (all four sizes confirmed from the publisher autoindex 2026-11-02). Rejected
  `CTU-IoT-Malware-Capture-60-1` (pcap is **21 GB**). IP strings in the filenames are the dataset's
  own published lab addresses, not Assas-network data.
- **Full archive — only if per-capture proves insufficient:** `iot_23_datasets_full.tar.gz` =
  21,510,801,277 B (~20.0 GiB), **publisher `md5:7132e603f9750b8580b6cebdbcd43e9c`**. Use of the
  archive requires separate approval and an expected extracted size (not published; estimated from
  the `.capinfos` metadata beforehand).
- **Checksums:** record publisher-provided values where available (the archive md5 above; per-capture
  `.capinfos` is capture metadata, not a hash). **SHA-256 is computed after download, never before.**

### CICIoT2023 (Canadian Institute for Cybersecurity, UNB) — ON HOLD (not in the first approval)
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

### Download procedure (original plan, not used)
The replay host and isolated network (§2) are finalized **first**. On approval, the selected files
are downloaded **onto the replay host** (not the Pi); each file's size is confirmed against the
autoindex, SHA-256 is computed after download and recorded here, then replay follows.

---

## 2. Replay environment and method — not used (offline method used instead)
> **Not used:** the replay method below was not used; the captures were read offline by Suricata on the appliance instead (`appliance/tools/IOT23_OFFLINE_TEST.md`).

Original plan (kept as a record): this setup was to be fixed before any dataset was downloaded.
- **Goal:** replayed traffic must reach the monitored interface `eth1` (the SPAN/mirror port),
  exactly like live monitoring — not injected into the appliance's own stack.
- **Replay host:** a dedicated second machine on an **isolated lab network** (no bridge to the
  production LAN). **Datasets are downloaded and stored on this host**, which runs `tcpreplay`. The
  Pi downloads nothing and only receives the mirrored copy on `eth1`.
- **Wiring:** replay host → a switch port that is mirrored (SPAN) to the port Suricata watches, so
  replayed packets appear on `eth1`. (If no managed switch: replay onto the mirror source segment.)
  Final host spec, OS and disk free recorded here once set up.
- **Switch port map and mirror settings** (TP-Link TL-SG105E, recorded 2026-11-23):

  | Port | Connected to |
  |---|---|
  | 1 | Home router |
  | 2 | Assas-Test access point |
  | 3 | Pi management interface (`eth0`) |
  | 4 | Pi capture interface (`eth1`) |
  | 5 | Spare (for a wired laptop) |

  Port Mirror: **enabled**; source **Port 2** (ingress + egress); destination **Port 4**. Only
  traffic that passes through Port 2 is copied to `eth1`; what this covers was verified in §5.
- To record per run: replay host + OS, `tcpreplay` version and exact command (incl. `--intf`,
  pps/`--mbps`, loop), switch mirror config, start/stop timestamps, the pcap(s) and their SHA-256,
  and the **ET Open rules date/version** in use.
- Detection is measured from **raw Suricata `alert` events (pre-dedup)** in `eve.json`, matched to
  each attack by **time window + addresses**; an alert merely appearing during replay does **not**
  count.

### Commands prepared for the replay method (not used)
All on the **replay host** (never the Pi). `BASE` = the IndividualScenarios URL above.

```bash
# (a) download the four approved captures + record size and SHA-256
mkdir -p ~/iot23 && cd ~/iot23
for u in \
  "CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap" \
  "CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap" \
  "CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap" \
  "CTU-Honeypot-Capture-7-1/Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap"; do
  curl -fLO "$BASE/$u"
done
ls -l *.pcap && sha256sum *.pcap | tee SHA256SUMS   # recorded into this file on download

# (b) replay one capture onto the mirrored segment (per run: record the exact
#     command, timestamps, and the rules version)
date -u +%FT%TZ   # start marker
sudo tcpreplay --intf1=<replay-NIC> --mbps=10 <capture>.pcap
date -u +%FT%TZ   # stop marker
```

On the **Pi** (read-only measurement, per attack window) — the committed,
unit-tested tool `appliance/tools/measure_detection.py`:
```bash
python3 appliance/tools/measure_detection.py \
  --start 2026-11-06T12:00:00 --stop 2026-11-06T12:20:00 \
  --addr 192.168.1.195 \
  --save docs/sprint-2/evidence/detection/<capture>-slice.jsonl
```
It counts RAW pre-dedup alert events from eve.json (live + rotated), matched by
the time window AND the capture's own lab addresses — co-occurrence alone never
counts (`appliance/test_measure_detection.py`). **Scope of this output: it
establishes that an alert RELATES to the replayed test traffic — it does NOT by
itself establish that the labelled attack was correctly detected.** The
detection judgement in §3 additionally requires mapping each fired signature's
semantics (rule message/classtype) to the capture's labelled attack class;
signatures unrelated to the label are recorded but do not count as detection.
Undetected attacks are recorded as such, and alerts raised on the benign
capture are recorded as false positives. This replay-based measurement was not
run (see the note at the top of this section).

## 3. Detection results — ☑ Done (IoT-23, offline, 23-24 November 2026)
Each malware capture was classified from the alert events that involve the infected device:
**Strong** (at least one event from a signature classified as malware or command-and-control),
**Indirect** (no such event, but at least one priority 1 or 2 event), **Weak** (only priority 3
events), **Not detected** (no event involves the device). Malware names are the dataset's own labels
(`appliance/tools/iot23_scenarios.txt`).

| Capture | Malware | Category |
|---|---|---|
| 1-1 | Hide and Seek | Indirect |
| 3-1 | Muhstik | Strong |
| 7-1 | Linux.Mirai | Indirect |
| 8-1 | Hakai | Not detected |
| 9-1 | Linux.Hajime | Indirect |
| 17-1 | Kenjiro | Strong |
| 20-1 | Torii | Not detected |
| 21-1 | Torii | Not detected |
| 33-1 | Kenjiro | Strong |
| 34-1 | Mirai | Indirect |
| 35-1 | Mirai | Indirect |
| 36-1 | Okiru | Indirect |
| 39-1 | IRCBot | Indirect |
| 42-1 | Trojan | Indirect |
| 43-1 | Mirai | Indirect |
| 44-1 | Mirai | Indirect |
| 48-1 | Mirai | Indirect |
| 49-1 | Mirai | Strong |
| 52-1 | Mirai | Indirect |
| 60-1 | Gafgyt | Not detected |

- **Result:** alerts on the infected device in **16 of 20** malware captures: 4 Strong, 12
  Indirect, 0 Weak, 4 Not detected.
- **Totals:** 14,783,458 alert events, 1,096 alerts after grouping. Every stored alert was
  associated with the infected device.
- **Benign captures** (Philips Hue, Amazon Echo, Somfy door lock): no alert on any device (one
  low-severity protocol event in the Philips Hue capture was not associated with a device).
- Precision and recall were not computed.
- The signature set has partial coverage by design: undetected attacks are recorded as such, with
  no full-coverage assumption.
- Full results are in Chapter 5 of the project report.

## 4. Resources — ☑ Three 2-hour runs (5 and 17 November 2026)

All resource and reliability measurements in this document are preliminary Release 1 measurements. Formal non-functional requirement testing is scheduled for Release 2.

Each run was taken with only the appliance services running, using
`appliance/tools/resource_sampler.py` (2 hours, one sample every 10 s). The sampler reads
`/proc/stat` (total-device CPU 0–100%), `/proc/meminfo` (`MemTotal − MemAvailable`, in MiB),
`/sys/class/net/eth1/statistics` (throughput, bits per second) and the eve `stats`
`capture.kernel_packets` / `kernel_drops` deltas (drop rate).

**Targets as the sampler judges them** (`resource_sampler.py`): CPU — the **average** is at most
75%; memory — the **maximum** is below 4096 MiB (4 GiB). Memory is total-device memory, not
adjusted by excluding any process.

| Run (UTC) | Traffic on `eth1` (avg) | CPU avg / max | Memory avg / max | Suricata packets dropped | CPU target | Memory target | Evidence |
|---|---|---|---|---|---|---|---|
| 5 Nov 2026, 02:26–04:26 | 6.58 Mbps | 36.7% / 53.4% | 3.95 / 4.37 GiB | 0 of 6,193,620 (drop measurement not validated, see below) | met | **not met** | `evidence/resources/clean/` |
| 17 Nov 2026, 16:32–18:32 (light traffic) | 1.2 Mbps | 9.8% / 32.7% | 2.36 / 2.38 GiB | 0 of 1,320,585 | met | met | `evidence/resources/clean2/` |
| 17 Nov 2026, 20:24–22:24 (heavier traffic) | 10.5 Mbps | 17.4% / 35.1% | 2.40 / 2.49 GiB | 0 of 9,162,670 | met | met | `evidence/resources/clean4/` |

Each evidence folder holds `resource-2h-summary.json` and `resource-2h.csv` (720 samples). Memory is shown in GiB (MiB ÷ 1024); the summaries record MiB.

- **5 November:** the CPU target was met; the memory target was not met (maximum 4470 MiB, above
  4096 MiB; average 4046 MiB). The audit below records what the memory consisted of.
- **17 November:** in both runs the CPU and memory targets were met, Suricata dropped no packets,
  the Suricata process stayed the same throughout (`suricata_pid_changes` 0) and the summaries mark
  the drop measurement as valid. Before both runs, the on-device display application was changed to
  stop its continuous animations (commit `54c05d1`, pull request #30, "Stop endless animations on
  the Pi display to cut GPU memory", committed on 17 November 2026 at 15:33 UTC). The project report
  treats the heavier-traffic run as the representative result.

### Memory accounting + units audit for the 5 November run (read-only, 2026-11-05)

**Units audit (tool definition vs acceptance criterion):** `/proc/meminfo`
values are KiB, so the sampler's figures are **MiB** and its 4096 threshold is
**4 GiB (= 4.295 GB decimal)**; against a literal **4 GB (decimal)** the bound
would be 3815 MiB. Readings of the 5 November run under each interpretation:

| Basis | avg 4046 MiB | max 4470 MiB |
|---|---|---|
| < 4 GiB (4096 MiB) | under | **over** |
| < 4 GB decimal (3815 MiB) | **over** | **over** |

The recorded verdict (max < 4 GiB → **NOT met**) **stands unchanged** under
every interpretation of the maximum; the team should still pin the criterion
(GB vs GiB, average vs maximum) for the report. The sampler now labels its
units explicitly (`mem_units` in the summary; CSV header `mem_used_mib`).

**What actually consumes the memory** (meminfo components, not an RSS guess):
`used = MemTotal − MemAvailable` = anonymous pages + shmem + unreclaimable
kernel memory (reclaimable page cache excluded). At inspection:
AnonPages ≈ 2163 MiB (process heaps — Suricata ≈ 1205 MiB dominant; the
inspection-time figure also includes ≈ 447 MiB from a process that is not part
of the appliance and was not running during the run), **Shmem ≈ 1740 MiB**, kernel unreclaimable ≈ 160 MiB,
plus the MemAvailable heuristic margin.

**Shmem distribution — what is PROVEN vs not (unprivileged vantage):**
- `ShmemHugePages` and `ShmemPmdMapped` are both **0** — no huge-page shmem.
- SysV shared memory (`ipcs -m`) totals **0 MiB**.
- tmpfs files (`df -t tmpfs`, all mounts) total **≈ 342 MiB** (mostly `/tmp`,
  `/run`).
- That leaves **≈ 1400 MiB of Shmem UNATTRIBUTED from an unprivileged vantage.**
  Readable per-process shared mappings sum to only ≈ 439 MiB *and that
  double-counts* pages shared between processes, so it does not close the gap.
  Suricata's `smaps_rollup` is root-only here, and GEM/dma-buf graphics
  allocations are not enumerable without privilege. **Therefore the earlier
  claim that the Shmem bulk is graphics buffers is NOT established** — it is a
  plausible candidate (anonymous shared memory on a Wayland system commonly
  holds compositor/client surface buffers) but unproven. Settling it needs
  privileged accounting, e.g. `sudo cat /proc/<suricata-pid>/smaps_rollup`,
  `sudo grep -r . /sys/kernel/debug/dri/*/clients` or a GEM/dma-buf breakdown,
  and `sudo smem -t` for a PSS table across all processes.

**Candidate improvements — HYPOTHESES only, none applied, none quantified until
the breakdown above exists (criterion, display and services unchanged):**
1. Suricata detect-engine profile: the deployed config uses
   **`detect.profile: medium`** (confirmed in `appliance/suricata/assas.yaml`,
   not `low`), `sgh-mpm-context: auto`, `toclient/toserver-groups 3/25`. A `low`
   profile *may* reduce the ≈ 1.2 GiB engine footprint at some CPU/detection
   cost — **expected impact UNKNOWN; must be measured before/after** if the team
   approves a trial. No number is claimed here.
2. Display-pipeline footprint (resolution/buffer count, VNC-on-demand): only
   worth pursuing **if** the privileged breakdown confirms graphics buffers hold
   the unattributed ≈ 1.4 GiB; expected saving cannot be stated until then, and
   it touches the screen pipeline so it needs product approval regardless.
3. Report an appliance-scoped figure (sum of the five services) alongside the
   total-device figure so the target can be judged on what the product actually
   controls (reporting change only — safe, no runtime effect).

### Drop measurement — validated in the 17 November runs
The 5 November summary records 0 drops but marks the drop measurement as not valid
(`suricata_drop_measurement_valid: false`): the sampler looked for a process named `suricata`,
while the kernel reports Suricata's process name as `Suricata-Main`, so no Suricata process ID was
recorded. This was a defect in the measurement tool, not in the service. The sampler was fixed
(`resource_sampler._is_suricata_comm`, with a regression test) and now records the Suricata
process ID at every sample (`suri_pid` CSV column; `suricata_pid_changes`, `suricata_pids_observed`
and `suricata_pid_missing_samples` in the summary), so a mid-run restart invalidates the
measurement. Both 17 November runs were taken with the fixed tool: one Suricata process ID
throughout, 0 missing samples, and `suricata_drop_measurement_valid: true`. The 5 November drop
figure stays recorded but not validated.

### Additional Release 1 runs (24-25 November 2026)
Evidence: `evidence/release1/b7-restart.txt` and `evidence/release1/b8-summary.txt`.

- **Restart test (24 November 2026, 21:58–22:02, +03:00).** `assas-discovery`, `assas-api`,
  `assas-alerts` and `assas-suricata` (all `Restart=always`, `RestartSec=5s`) were each stopped once
  with `KILL` and once with `TERM`. Each came back with a new process ID after 5.1–5.3 s, except
  `assas-suricata` after `TERM` (7.4 s). Time until ready: `assas-api` 5.8 s (`KILL`) and 6.0 s
  (`TERM`); `assas-suricata` 15.8 s and 17.9 s. `NRestarts` went from 0 to 2 for each service, and
  all four were `active` at the end. Database row counts before and after were the same in every
  table except `flows` (3,940,332 → 3,941,721).
- **8-hour run (24 November 2026, 22:08 to 25 November 2026, 06:08, +03:00).** 97 samples over 480
  minutes. For `discovery`, `api`, `alerts` and `suricata`: 0 samples not active, 0 restarts, one
  process ID each. The display app was running in every sample. Alerts rows went from 102 to 103 and
  never decreased (0 read errors); devices rows stayed at 65. Memory used: average 2573 MiB, maximum
  2758 MiB. CPU: average 9.6%, maximum 18.1%. Suricata memory: 1178 MiB at the start, 1183 MiB at
  the end and at most.

## 5. Capture scope verification (B4) — ☑ Done (2026-11-23)

The project states its capture scope: traffic analysis is limited to communications visible
through the mirrored port, and communications that do not traverse the monitored ports are outside
that coverage. This planned check verified that stated scope on the switch setup recorded in §2.

**Method:** ICMP pings from a laptop on Assas-Test to a phone, with a capture running on the Pi's
capture interface. The packet counts are the ones tcpdump reports when the capture is stopped.
```bash
sudo tcpdump -i eth1 -nn icmp and host <laptop-address> and host <phone-address>
```

| Round | Setup | Pings sent / replies | Captured on `eth1` | Dropped | Visible? |
|---|---|---|---|---|---|
| 1 | Laptop on Assas-Test → phone on the home router Wi-Fi | 10 / 10 | 20 | 0 | Yes |
| 2 | Laptop and phone both on Assas-Test (phone Wi-Fi screen confirmed) | 10 / 10 | 0 | — | No |
| 3 | Repeat of round 2 | 30 / 29 | 0 | — | No |
| 4 | Control, right after round 3: phone back on the home Wi-Fi | 30 / 30 | 60 of 60 | 0 | Yes |

Round 4 shows the capture was working during rounds 2 and 3.

**Result: consistent with the stated scope.** Traffic that crosses the access point uplink (Port 2)
is visible: traffic between Assas-Test devices and the router, wired devices, home Wi-Fi devices or
the internet. Traffic between two devices on the same access point is forwarded by the access point
itself and does not reach the mirrored port, so it is outside the capture coverage.

**Design reason:** Assas is out-of-band. It receives a copy of the traffic and is not in the
forwarding path, so if the Pi fails, the home network keeps working.

**Possible future improvement:** the Pi acting as the Wi-Fi access point could also see
client-to-client traffic; this is a design change, not planned for Release 1.
