# Proposal — Reliable IPv6→Device Attribution

**Status: pending approval; not implemented.**

Objective (team-approved direction; the plan itself awaits final approval):
link alerts to devices by **observed MAC evidence**, never by network-prefix
membership. Once linked, the existing dedup (same rule + same
device within the 5-minute window) collapses today's per-CDN fan-out (e.g. the
22:15 rule-2210016 group: 20+ rows → ~1 row per burst). This does **not** merge
time-separated alerts (> window) and does **not** address protocol-rule noise —
both intentionally out of scope here.

## Grounding (verified in code)
- `discovery.py` sniffs the SPAN interface (eth1) and calls
  `update_device(mac, ip=…)` for observed frames; `_ip_family_column()` then
  stores only the **latest** IPv6 per family (`last_ipv6_global` /
  `last_ipv6_ll`). Privacy (RFC 4941) addresses rotate, so alert addresses often
  aren't the stored one → 200 unlinked IPv6 alerts (see
  `evidence/partD-alert-data-investigation.md`).
- `alerts.py: link_device()` matches only those single-value columns; on 0
  matches → NULL (correct but blind to rotated addresses).

## Change 1 — discovery records the address **set** (additive)
New table, created by discovery alongside its other DDL:
```sql
CREATE TABLE IF NOT EXISTS device_ipv6 (
  mac        TEXT NOT NULL,
  addr       TEXT NOT NULL,          -- normalized (exploded lowercase) IPv6
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  source     TEXT NOT NULL,          -- 'span' | 'ndp'
  PRIMARY KEY (mac, addr)
);
CREATE INDEX IF NOT EXISTS idx_device_ipv6_addr ON device_ipv6(addr);
```
Writers — ownership must be proven, never assumed from the frame:

> **The frame-MAC pitfall:** on the SPAN, traffic arriving *from the internet*
> carries the **router's** MAC as `Ether.src` with an **external** IPv6 source.
> Recording raw `(Ether.src, src IPv6)` pairs would therefore register external
> server addresses under the router's MAC. Every writer below must prove the
> address belongs to a **local device** first.

1. **NDP (authoritative):** sniffed ICMPv6 Neighbor Solicitation/Advertisement
   options (SLLA/TLLA) and DAD assert on-link `addr↔MAC` ownership — these are
   the primary evidence (`source='ndp'`). Also parse the kernel cache
   (`ip -6 neigh show`) via a pure, unit-testable `parse_ndp_neighbors(output)`;
   **entries in `INCOMPLETE`/`FAILED`/`NONE` states are discarded** — an
   unanswered solicitation proves nothing about ownership.
2. **Observed traffic (guarded, secondary):** inside `update_device()`, upsert
   `(mac, addr)` (`source='span'`) **only when all guards pass**:
   - the IPv6 source is **on-link local** (within a monitored network from
     `load_ipv6_context()`, or ULA/link-local) — never an off-link address;
   - the frame MAC is **not the gateway/router MAC** (the inventory's gateway
     record; routers front every external address);
   - **fan-out cap:** once a single MAC accumulates more than N distinct global
     addresses (default 16, router-like behaviour), new pairs for that MAC are
     rejected and logged instead of trusted.
   Wrapped in try/except so it can never break sniffing; the existing
   write-cache throttle bounds the overhead.
Retention: rows are never ownership-proof by mere existence (see linking rule);
no deletes this sprint (table is tiny).

## Change 2 — alerts.py consults the set (same rules as today)
In `link_device.resolve(ip)`, for IPv6 also query `device_ipv6`. Linking is
decided by the event time against the ownership-evidence window, not by the
mere existence of a record:
```sql
SELECT DISTINCT mac FROM device_ipv6
WHERE addr = ?
  AND datetime(first_seen, '-2 hours')      <= <event_time>   -- clock skew / first-sighting lag
  AND datetime(last_seen,  '+24 hours')     >= <event_time>   -- deprecated-address grace
```
Rationale for the bounds (both configurable, both a stated trade-off — the lower
bound **does allow** attributing events up to 2 h before the first proof; it does
NOT exclude "everything older than the evidence"):
- **Lower bound `first_seen − 2h`** (`ASSAS_IPV6_LINK_PRE_SLACK`): ownership
  evidence necessarily lags first use — a fresh privacy address sends traffic
  before our NDP capture / periodic neighbor poll first records the pair. Since
  a privacy IID belongs to exactly one device for its lifetime (collision
  negligible), traffic in that short pre-proof gap is attributed to the device
  that then proved ownership. Accepted, bounded risk: anything **more than 2 h
  older than the first evidence** (e.g. a replayed old capture) stays NULL.
- **Upper bound `last_seen + 24h`** (`ASSAS_IPV6_LINK_GRACE`): a deprecated
  RFC 4941 address keeps *receiving* traffic after it stops being preferred,
  until its valid-lifetime expires; 24 h is a conservative slice of that.
The ingester normally processes events near-real-time, so live events fall
inside the window naturally. Unioned with the existing column match. Decision
rules **unchanged**:
- exactly one distinct MAC → link;
- more than one → NULL + log (ambiguity never guessed);
- zero → NULL. **No prefix matching** — an address merely inside the home /64
  never links.
- Missing `device_ipv6` table (old DB / discovery not yet updated) → treated as
  zero rows; behavior identical to today (graceful rollout, either service can
  deploy first).

## Ownership-proof tests (written with the implementation, must pass before deploy)
`test_alerts.py`:
1. `device_ipv6` maps addr→mac A only → `link_device` returns A (even when
   `devices.last_ipv6_global` holds a different, newer address).
2. Two MACs claim one addr → NULL (ambiguity kept).
3. **Prefix-only is never enough:** addr shares the /64 of an inventoried device
   but is absent from `device_ipv6` → NULL.
4. **Router-MAC exclusion:** a stream of SPAN frames carrying
   the gateway MAC with *external* IPv6 sources must create **no** `device_ipv6`
   rows — and those alerts stay NULL (never attributed to the router).
5. **Evidence-window linking — boundaries tested on both sides:** with evidence `[first, last]`:
   `first − 1h59m` → **link** (inside the pre-slack, by design);
   `first − 2h01m` → NULL (replayed old capture);
   `last + 23h59m` → **link**; `last + 24h01m` → NULL.
   `INCOMPLETE`/`FAILED` neighbor entries are ignored by the parser (unit test).
6. **Fan-out cap:** after N distinct global addresses on one MAC, further pairs
   are rejected + logged.
7. **End-to-end collapse:** one device with a *proven* (NDP-sourced) privacy
   addr mapping whose window covers the events; 5 eve events, same rule, 5
   different CDN sources, within 2 min → **one** row, occ=5, linked (the
   22:15-cluster fix — valid only because ownership of the destination address
   is actually established first).
8. No `device_ipv6` table → identical to current behavior.
`test_discovery.py`: `parse_ndp_neighbors` parsing + `device_ipv6` upsert
(first_seen kept, last_seen bumped, PK dedupe).

## Sprint-1 preservation
Additive only: new table + one guarded hook in `update_device` + one periodic
poll; **no** changes to `devices` columns, API shapes, classification, pairing,
or capture. Full suites (appliance 519+, mobile 76, discovery/flows tests) must
stay green; the hook's failure mode is "no row written", never a sniff error.

## Rollout (after implementation approval)
1. Implement + tests green → commit to `sprint-2`.
2. Deploy batch (short sudo): `sudo systemctl restart assas-discovery.service
   assas-alerts.service` (either order; both tolerate the other being old).
3. Live check (read-only): watch `device_ipv6` row growth; after the next CDN
   burst, confirm the group lands as ~1 linked row instead of ~20 unlinked.
   Historical unlinked alerts are **not** rewritten (no data mutation).
