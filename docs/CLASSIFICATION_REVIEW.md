# Classification review — 2026-10-16

Reviewed classification rules for DHCP option 55/60, model identifiers,
hostnames, vendor hints, DNS/mDNS queries, service advertisements, port hints,
TCP SYN fingerprints and candidate scoring. Inspected their discovery call
sites; this is not a guarantee of correctness for every hardware model.

Additional regressions fixed:

- Pixel Tablet now resolves to Tablet (Android), including hostname evidence.
- Galaxy/Pixel Watch, Galaxy Buds and Galaxy Book no longer acquire the
  Mobile (Android) label just from their product family.
- DNS hints require a complete configured domain or its subdomain. Incidental
  substrings and bare brand keywords no longer identify a device.
- mDNS query hints require the complete service suffix in the local domain.

Follow-up fixes:

- DNS query destinations no longer infer client type or vendor, including
  connectivity-check endpoints. Genuine service advertisements remain usable.
- Equal-strength conflicting types produce Generic / Unknown with the original
  confidence barrier. Repetition or weaker evidence cannot pick a winner;
  stronger evidence can resolve the conflict. This applies across observations
  as well as within a packet.
- Startup resets classifications reproducible from saved evidence and rebuilds
  them with current rules. Retired DNS classifications and DNS-inferred vendors
  are cleared. Live-only service evidence and existing conflict barriers survive.
  Inventory identity, timestamps and monitoring state are preserved.

Validation: full backend tests include repeated database migration, preserved
inventory, retired DNS evidence, retained service evidence and conflicts across
updates. No deployment or GitHub push was performed.

Remaining limits: vendor/port fingerprints are heuristics, model coverage is
finite, and real hardware validation is still required. Historical conflicts
whose competing observations were never retained cannot be reconstructed;
new observations are handled conservatively.
