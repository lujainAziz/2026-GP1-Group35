# Internal scan detection after the EXTERNAL_NET change

Date: 2026-11-13 and 2026-11-14 (times are local, UTC+03:00)

## What happened
On 2026-11-13 at 19:25 to 19:26, Assas raised four alerts within about one minute. All four had the same source: a team laptop connected to the Assas-Test Wi-Fi. All four had the same destination: the Assas-Test router. Assas linked all four alerts to the laptop.

| Time | Rule (SID) | Severity | Destination port |
|---|---|---|---|
| 19:25:33 | ET SCAN Suspicious inbound to MSSQL port 1433 (2010935) | High | 1433 |
| 19:25:33 | ET SCAN Suspicious inbound to mySQL port 3306 (2010937) | High | 3306 |
| 19:26:31 | ET TFTP Outbound TFTP Read Request (2008120) | Critical | 69 |
| 19:26:31 | GPL DNS named version attempt (2101616) | High | 53 |

The two database-port alerts used the same source port in the same second, which is the pattern of a scan rather than normal use.

## Source of the traffic
The laptop runs Norton. Norton's Smart Scan has three steps; the second is "Network", which checks the router. Norton showed its last scan at 2026-11-13 7:33 PM, matching the time of the alerts.

To confirm, Smart Scan was run again by hand on 2026-11-14 with the laptop on Assas-Test:

| Time | Rule (SID) | Severity |
|---|---|---|
| 02:03:49 | 2010935 (MSSQL 1433) | High |
| 02:03:49 | 2010937 (mySQL 3306) | High |
| 02:04:43 | 2008120 (TFTP read) | Critical |

Same laptop, same router, same rules. 2101616 did not appear in the second run; the reason is not known.

## Why this depends on the EXTERNAL_NET change
The rule headers on the device (checked 2026-11-14):

- 2101616: `alert udp $EXTERNAL_NET any -> $HOME_NET 53`
- 2010937: `alert tcp $EXTERNAL_NET any -> $HOME_NET 3306`
- 2010935: `alert tcp $EXTERNAL_NET any -> $HOME_NET 1433`
- 2008120: `alert udp $HOME_NET any -> [$EXTERNAL_NET,!255.255.255.255] 69`

Both the laptop and the router are inside the home network. With the old setting `EXTERNAL_NET: "!$HOME_NET"`, none of these four rules could match: the first three need an outside source, and the fourth needs an outside destination. With `EXTERNAL_NET: "any"` (applied 2026-11-11), all four matched.

## Decision
These are correct detections, not noise. The four rules stay enabled and are excluded from rule tuning round 4.

## Limits
- This shows detection of a light network check by a security product, not a full attack.
- Only traffic that crosses the access point is mirrored to Assas.
- IP and MAC addresses are left out of this file on purpose.
