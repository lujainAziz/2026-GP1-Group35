# Proposal — reliable IPv6→device attribution (plan only, not implemented)

Approved direction: link alerts to devices by **observed MAC evidence**, never by
network-prefix membership. Once linked, the existing dedup (same rule + same
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
Writers (both are MAC-grounded evidence, no inference):
1. **Observed traffic (primary):** inside `update_device()` where the IPv6
   family column is already written, also upsert `(mac, addr)` bumping
   `last_seen` (`source='span'`). Wrapped in try/except so it can never break
   sniffing (house rule in that file). The existing write-cache throttle keeps
   the overhead at one upsert per MAC/address change.
2. **NDP (secondary):** on the existing periodic cadence, parse
   `ip -6 neigh show` (REACHABLE/STALE → `addr lladdr mac`) via a **pure,
   unit-testable** `parse_ndp_neighbors(output)` and upsert (`source='ndp'`).
   Read-only command; covers hosts the Pi itself exchanges NDP with.
Retention: rows age out only via the linking recency guard (below); no deletes
this sprint (table is tiny).

## Change 2 — alerts.py consults the set (same rules as today)
In `link_device.resolve(ip)`, for IPv6 also query:
```sql
SELECT DISTINCT mac FROM device_ipv6
WHERE addr = ? AND last_seen >= <now - ASSAS_IPV6_LINK_MAX_AGE (default 14d)>
```
unioned with the existing column match. Decision rules **unchanged**:
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
4. Mapping older than the recency guard → NULL.
5. **End-to-end collapse:** one device with a mapped privacy addr; 5 eve events,
   same rule, 5 different CDN sources, within 2 min → **one** row, occ=5,
   linked (the 22:15-cluster fix, asserted).
6. No `device_ipv6` table → identical to current behavior.
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
