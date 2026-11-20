# Alert data investigation (read-only) — unlinked alerts & large count

Read-only analysis of the production DB (`assas.db`, `mode=ro`) cross-checked
against the live `/var/log/suricata/eve.json` on 2026-11-04. **No rows deleted,
no rules/severity changed, no synthetic events written.** Snapshot: 577 Threat
rows, SUM(occurrence_count)=5119, 39 distinct rules, event window
2026-11-02T15:40 → 2026-11-04T20:01.

## Item 4 — why the count is large (not an attack, not a dedup bug)

**Distribution**
- By state: New 575 (occ 3619), Reviewed 1 (occ 218), Resolved 1 (occ 1282).
- By severity: **all 577 are Medium** — every firing rule has Suricata priority 3
  (`1→Critical, 2→High, 3→Medium, ≥4→Low`), so nothing maps to Critical/High/Low.
- Top rules (rows / occ): ET INFO Discord Domain in DNS Lookup 144/2086; SURICATA
  STREAM CLOSEWAIT FIN out of window 141/245; SURICATA STREAM excessive
  retransmissions 71/75; more ET INFO Discord 42/32; SURICATA TCP option invalid
  length 19/394; ET FILE_SHARING file-sharing domain 11+11; ET INFO Android
  connectivity check 9.

**Classification:** the volume is dominated by **informational** rules (ET INFO
Discord/connectivity/file-sharing *domain in DNS/TLS* — benign lookups; category
"Misc activity") and **decoder/stream-engine** events (SURICATA STREAM / TCP
option / IPv6) — network noise, not threat indicators. Confirmed against eve.json:
rule 2035465 is a real `ET INFO ... DNS Lookup`, category "Misc activity",
priority 3, with a src_ip.

**Is it real events, re-duplication, or a dedup/resume bug?** Real events.
- Dedup is working: 577 rows compress 5119 events.
- No merge failures: **0** linked rows start within the 300 s window of the
  previous same-rule+device alert (query with a window-function LAG). The many
  rows per rule+device (e.g. 144 Discord rows on one device over ~2 days) are all
  spaced **> 300 s** apart → legitimately separate instances, not re-dup.
- The P1 ingester fixes (fstat identity, reaper, resume) already landed; no
  inflation from re-reads is present in this snapshot.

**Recommendation (NOT applied — proposal only, per instruction):** do not delete
rows or change rules/severity to shrink the number. If desired, a *separate*
proposal is to (a) surface a rule-class label so informational/decoder events are
visually distinct from threat-indicative ones, and/or (b) tune noisy decoder
rules — each with its own before/after evidence. Validation limit: rotated eve
files are reaped per retention, so events older than the retained window can't be
re-matched line-by-line.

## Item 3 — alerts with device_mac = NULL (202 of 577)

Classified read-only:
| Reason | Count |
|--------|-------|
| (a) event has no addresses (decoder) | 2 |
| (b) addresses present, **no** inventory match | 200 |
| (c) address matches **>1** device (ambiguous → NULL by design) | 0 |
| (d) address matches **exactly one** device but was left NULL (**would be a bug**) | **0** |

**(d) = 0 → the linker has no bug:** every alert that could be reliably attributed
*is* linked (IPv4 links fine). Nothing is left Unknown that should have linked,
and nothing is linked arbitrarily.

**Root cause of the 200:** they are **all IPv6** (0 IPv4). 189 of 200 carry a home
address in the prefix `2001:db8:dea6:2200::/64` (e.g.
`dst=2001:0db8:dea6:2200:79ee:14d2:e191:965e`) talking to an external host
(Facebook/Cloudflare/Google IPv6). That home address is a **temporary/privacy
SLAAC address** that is **not** the single global IPv6 the inventory stored for
the device (inventory has e.g. `...:2200:6854:...` for a device in the same /64).
Devices rotate privacy addresses and the /64 holds several devices, so matching by
the stored address fails and matching by prefix would be **ambiguous** — the
device-linking rule therefore correctly leaves `device_mac = NULL` rather than guess.

**Proposal (NOT applied — needs approval + a discovery/inventory change, outside
the "link only when reliable" rule):** attribute IPv6 flows to devices by tracking
each device's *set* of current IPv6 addresses (from the NDP neighbour cache /
observed traffic), so privacy-address flows resolve to the owning MAC. Prefix-only
matching is not added because it is not a reliable host match.

## Follow-up: the 22:15 "CLOSEWAIT FIN out of window" group (rule 2210016)

Focused read-only analysis of the rule-2210016 cluster observed 22:15–22:25 on
2026-11-04 (nothing deleted, no rule disabled, no dedup change).

**Facts (matched 1:1 against eve.json):** 26 rows, SUM(occurrence)=**32**, and
eve.json holds exactly **32** matching events in the window — two synchronized
bursts (23+1 events at 22:15:48–:49, 8 at 22:25:03). Source/destination pairs are
**different**: 21 distinct CDN IPv6 sources (Google/Cloudflare/Amazon/Microsoft…)
toward one local privacy-IPv6 destination (unlinked by design) plus one linked
IPv4 row (→ the TV). Dedup integrity: 22 distinct keys; the only repeated keys
recur **555 s apart (> the 300 s window)** → correctly separate rows; **0 pairs
should have merged**. So: not duplicate storage, and not 26 attacks — a stream-
engine protocol anomaly, one event-set per row.

**Interpretation — calibrated:** the pattern (many idle sessions to unrelated
CDNs tearing down in the same second, twice) is **consistent with** a single
device closing its connection pool at once (app close / wake). This is a
**plausible hypothesis, not a confirmed cause** — the capture does not identify
the initiating process. Likewise, `kernel_drops = 0` across the window (~1 M
packets) rules out drops **at the host's AF_PACKET layer only**; it does **not**
prove the whole capture path (switch SPAN port, mirror congestion, asymmetric
mirroring) was loss-free, so a capture-path contribution to the out-of-window
condition cannot be excluded.

**Decision recorded:** no dedup/grouping change and no deletions on account of
this group. Two proposals remain open for a product decision (not implemented):
(1) visually distinguishing protocol/stream-engine events from threat-indicative
rules; (2) improving IPv6 attribution by tracking each device's current IPv6
address set.

## Item 2 — missing source/destination addresses are genuinely absent

Only **2** alerts have no src/dst, both `SURICATA IPv6 truncated packet` decoder
events. Confirmed in eve.json: the event itself has **no** `src_ip`/`dest_ip`
(`has src_ip= False, has dest_ip= False`). So the blank addresses are real, not a
fetch/display loss, and the detail screen correctly omits the Source/Destination
IP rows (no fabricated values). All address-bearing alerts carry their src/dst
through the API to the screen.
