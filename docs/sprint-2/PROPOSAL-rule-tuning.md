# Proposal — Suricata rule-scope tuning (NOT applied; for approval)

Goal: alerts should flag **suspicious activity**, not normal usage (opening
Discord, OS connectivity checks). This tunes **which rules are enabled** — it
does **not** change the PBI-14 severity mapping, does not delete stored alerts,
and does not disable any category wholesale or "all Medium". Based on the
read-only inventory of all 39 rules that have fired (DB, 2026-11-02→04).

## Mechanism (persists across `suricata-update`)
`suricata-update` applies `/etc/suricata/disable.conf` (SID list) and
`threshold.config` on every run, so the tuning survives rule updates. Repo
copies become the source of truth: `appliance/suricata/disable.conf`,
`appliance/suricata/threshold.config` (new), deployed like the other configs.
Existing alert rows are kept untouched.

## Group A — normal-usage informational rules → propose **disable**
| SID | Rule | Volume (rows/occ) | Reason |
|---|---|---|---|
| 2035465 | ET INFO Observed Discord Domain in DNS Lookup (discord.com) | 149/2308 | Normal app usage (DNS lookup of discord.com) |
| 2035466 | ET INFO … (discordapp.com) | 49/180 | Same |
| 2060502 | ET INFO Discord Chat Service Domain in DNS Lookup (gateway.discord.gg) | 34/113 | Same |
| 2060503 | ET INFO Discord Chat Service Domain in DNS Lookup (discord.com) | 1/5 | Same |
| 2060504 | ET INFO Observed Discord Service Domain (gateway.discord.gg) in TLS SNI | 34/34 | Same |
| 2060505 | ET INFO Observed Discord Service Domain (discord.com) in TLS SNI | 1/1 | Same |
| 2035463 | ET INFO Observed Discord Domain (discord.com in TLS SNI) | 9/11 | Same |
| 2036220 | ET INFO Android Device Connectivity Check | 9/67 | Normal Android captive-portal/connectivity probe |
| 2031071 | ET INFO Microsoft Connection Test | 2/4 | Normal Windows connectivity probe |
| 2016149 | ET INFO STUN Binding Request | 2/29 | Normal WebRTC/VoIP NAT traversal (e.g. Discord calls) |
| 2016150 | ET INFO STUN Binding Response | 2/29 | Same |
| 2052580 | ET INFO DNS Query to Alibaba Cloud CDN (aliyuncs.com) | 1/6 | CDN lookup = normal usage (common for consumer IoT) — flagged for the team since it can also profile gray-market devices |

These 12 SIDs account for **~2,790 of 5,460 occurrences (~51%)** — pure
usage noise. Disabling is per-SID (no category/metadata matching).

## Group B — keep enabled (possible security signal, despite the volume)
| SID | Rule | Why kept |
|---|---|---|
| 2046656/2046657 | ET FILE_SHARING wasabisys.com (DNS/TLS) | Commonly-abused exfil/hosting bucket — worth attention |
| 2063117/2063118 | ET INFO Abused Hosting azurewebsites.net (DNS/TLS) | Abused-hosting indicator |
| 2014819 | ET INFO Packed Executable Download | Classic malware-delivery indicator |
| 2031231 | ET INFO Observed ZeroSSL Certificate | Free-cert phishing signal, negligible volume |
| 2033078 | ET INFO STUN Binding Request On Non-Standard High Port | The non-standard-port variant retains signal value |

## Group C — STREAM / decoder engine events (reviewed separately)
**Capture config first (checked, read-only):** `assas.yaml` keeps Debian stream
defaults (`midstream`/`async-oneside` off, kernel checksum mode);
`kernel_drops=0` in the observed windows. Notable: **sid 2200013 "IPv6
truncated packet" has occ=1595 from only 2 rows** — a strong hint that the
mirror forwards frames larger than the capture path accepts (router-side
GSO/jumbo frames truncated at the SPAN egress). **Action item before any rule
change:** check offloads/MTU (`ethtool -k eth1`, switch mirror settings). If
truncation is confirmed as a mirror artifact, these decoder events measure the
mirror, not the network.

Per-rule proposal (pick one per team decision):
| SIDs | Option 1 — threshold (recommended) | Option 2 — disable | Detection impact |
|---|---|---|---|
| 2210016, 2210054, 2210045, 2210020, 2210029, 2210050, 2210008, 2210010, 2210004, 2210023, 2210030, 2210046, 2210024, 2210027, 2210038, 2210044 (STREAM) | `threshold.config`: `type limit, track by_src, count 1, seconds 3600` per SID → at most one indicator/hour/source | remove from ruleset via disable.conf | Thresholding keeps a trace of TCP anomalies (occasionally useful against scans/evasion) while killing the burst noise; disabling loses that visibility entirely |
| 2200013, 2200036, 2200075, 2231000 (decoder/QUIC) | same thresholding | disable after the mirror-truncation check confirms they are capture artifacts | If truncation is a mirror artifact these alerts carry no network signal; if not, they still warrant an engine-health view, not a user-facing threat |

**Recommendation:** threshold Group C now (keeps evidence, ends the flood);
revisit disabling 2200013 only after the `ethtool`/mirror check.

## Verification plan (after approval, before sign-off)
1. `suricata-update` with the new `disable.conf` → record the rule-count delta;
   `sudo suricata -T -c /etc/suricata/assas.yaml` passes; restart unit.
2. **Normal usage no longer alerts:** open Discord / run an Android
   connectivity check on a LAN device → no new Group-A SIDs in `eve.json`.
3. **Security detection still works:** from a LAN host,
   `curl http://testmynids.org/uid/index.html` → `GPL ATTACK_RESPONSE id check
   returned root` (sid 2100498) fires end-to-end (eve → DB → app). Safe,
   standard NIDS self-test; no synthetic data written into logs by hand.
4. Existing alert rows remain untouched (count before == after tuning).

## Deployment batch (held until the list above is approved)
```bash
sudo install -m 0644 appliance/suricata/disable.conf    /etc/suricata/disable.conf
sudo install -m 0644 appliance/suricata/threshold.config /etc/suricata/threshold.config
sudo suricata-update   # applies disable.conf; one-shot, no scheduled updates added
sudo suricata -T -c /etc/suricata/assas.yaml -v
sudo systemctl restart assas-suricata.service
```
