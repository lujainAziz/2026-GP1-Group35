# Threat Alert titles and explanations

Source: Sprint 2 decision (2026-11-11): Option 2, updated by the Release 1 decisions
(see *Release 1 changes* at the end). The title in the alert list is a short plain-language name based on the rule classification (classtype); a few rules have their own text (see *Rule-specific messages*). The original Suricata rule name stays visible in the alert details. Titles must be clear and must accurately reflect the detected threat.

Classtypes below are the 39 that appear in the enabled rules on the device (counted 2026-11-14), ordered by number of enabled rules.

Writing rules used for this draft:
- The title says what was seen, not more. Words like "may", "possible" or "attempt" are used when the rule cannot prove the result.
- The explanation has two parts: what it means, and what the user can do.
- No title claims a device is infected unless the classtype says the activity was detected (not just attempted).
- Plain words instead of technical terms (no "domain", "exploit kit", "protocol" in titles).
- Low-concern groups say so in the title ("often harmless", "for your information"), so similar-looking titles are not confused.

## Device role line (agreed 2026-11-14)
An alert is linked to one device, but that device can be the one that started the activity or the one that was targeted (example: the Norton scan was linked to the laptop that did the scanning). The title stays neutral, and the alert details add one line from the stored source and destination:
- "This device started the activity." (the device is the source)
- "This device was the target." (the device is the destination)
The explanation is written so it reads correctly with either line.

| # | classtype | Enabled rules | Title (alert list) | Explanation (alert details) |
|---|---|---|---|---|
| 1 | trojan-activity | 10,173 | Possible harmful software | This traffic matches the behavior of known harmful software. A device may be infected. Run an antivirus scan on it and keep its apps updated. |
| 2 | bad-unknown | 7,426 | Suspicious traffic | A device used a website or service that attackers sometimes use, but normal apps use it too. No action is needed unless it keeps happening. |
| 3 | domain-c2 | 7,216 | Contact with a known harmful server | A device tried to reach an internet address known to control harmful software. This can happen after clicking a bad link, or if the device is infected. Run an antivirus scan on it. |
| 4 | web-application-attack | 6,017 | Attempt to attack a website | Someone sent a request that tries to break into a website or a device's settings page. If this device was the target, update its software. If it sent the request, run an antivirus scan on it. |
| 5 | misc-activity | 4,684 | Notable activity (often harmless) | This activity is often harmless but worth knowing about. No action is needed unless it keeps happening or you do not recognize it. |
| 6 | command-and-control | 3,626 | Harmful software contacting its controller | This traffic matches how harmful software talks to the computer that controls it. The device is likely infected. Disconnect it from the network if you can, and run an antivirus scan. |
| 7 | exploit-kit | 2,687 | Contact with a site that attacks devices | A device tried to reach a website linked to tools that break into devices through old browsers or apps. Update the device's browser and apps. |
| 8 | attempted-admin | 2,043 | Attempt to take full control of a device | Someone tried to get full control of a device or one of its features. Make sure the device uses a strong password and updated software. |
| 9 | social-engineering | 1,551 | Possible scam website | A device tried to reach or opened content that may be a scam, such as a fake sign-in page. Do not enter passwords or payment details on pages you do not trust. |
| 10 | credential-theft | 1,548 | Possible password theft | A device may have entered information on a fake page used to steal passwords. If you typed a password there, change it right away. |
| 11 | misc-attack | 1,323 | Traffic with a risky address | A device exchanged traffic with an internet address that security lists mark as risky. This is not always an attack. Watch whether it keeps happening. |
| 12 | targeted-activity | 978 | Contact linked to a hacking group | A device tried to reach an address linked to organized hacking groups. Run an antivirus scan on it. |
| 13 | attempted-user | 830 | Attempt to get into a device | Someone tried to get into a device or one of its features. Make sure it uses a strong password and updated software. |
| 14 | pup-activity | 667 | Unwanted app activity | This traffic matches apps that are often unwanted, such as apps that show ads or browser add-ons. Check the apps installed on the device and remove ones you do not need. |
| 15 | protocol-command-decode | 618 | Irregular network messages | Devices sent network messages that did not follow the expected format. This is usually harmless, but it can be part of an attack. No action is needed unless it keeps happening. |
| 16 | policy-violation | 543 | Activity many networks block | This is activity that many networks do not allow, such as file-sharing, chat or game apps, or sending information without protection. This is not always an attack, but it can put privacy or security at risk. Check that it is expected on this device. |
| 17 | attempted-recon | 279 | Attempt to learn about a device | Someone tried to learn about a device, such as what it runs. This is often an early step before an attack. Make sure the device's software is updated. |
| 18 | web-application-activity | 165 | Use of a website with known weaknesses | A device used a website or web page that has known security weaknesses. If the page belongs to this device, update its software. |
| 19 | external-ip-check | 146 | Device checked your internet address | A device asked an online service for your home's internet address. Many apps do this, but harmful software does too. Check the device only if you do not recognize it or it acts strangely. |
| 20 | unknown | 136 | Unclassified activity | This traffic did not fit a specific group. It is often harmless, but some of these checks look for signs of harmful software. Watch whether it keeps happening. |
| 21 | attempted-dos | 97 | Attempt to overload a device | Traffic tried to stop a device from working by flooding it with requests. If this device was the target and stopped responding, restart it. |
| 22 | not-suspicious | 76 | Normal activity (for your information) | This activity was recorded for information only. It is not considered suspicious. No action is needed. |
| 23 | shellcode-detect | 62 | Possible attack code | The traffic contains code that attacks often use to take over apps. Make sure the device's software is updated. |
| 24 | rpc-portmap-decode | 60 | Request to list what a device offers | A device was asked what network features it offers. This is normal on some networks, but attackers also do it before an attack. No action is needed unless it keeps happening. |
| 25 | coin-mining | 56 | Cryptocurrency mining activity | This traffic matches cryptocurrency mining, which uses a device's power to earn digital money. If you did not set this up, the device may be infected. Run an antivirus scan on it. |
| 26 | successful-admin | 53 | Someone may have taken full control of a device | The traffic suggests someone may have gained full control of a device. Check the device right away and change its passwords. |
| 27 | suspicious-filename-detect | 26 | Request for a suspicious file | A device asked for a file whose name is often used by harmful or password-stealing software. Do not run or install such files unless you expected them. |
| 28 | successful-recon-limited | 21 | Device may have shared private information | A device may have shared information about itself, such as its settings or user accounts. Make sure the device's software is updated. |
| 29 | network-scan | 21 | Network scan | A device searched the network to find other devices and what they offer. This is fine if you or an app you trust started it. Otherwise, check the device. |
| 30 | denial-of-service | 16 | Possible attack to stop a device | The traffic matches attacks that try to stop a device from working. If this device was the target and stopped responding, restart it and update its software. |
| 31 | suspicious-login | 14 | Suspicious sign-in activity | The traffic matches suspicious sign-in attempts or tools used to steal passwords. Make sure the device uses strong passwords. |
| 32 | unsuccessful-user | 12 | Failed attempt to get into a device | Someone tried to get into a device and failed. Keep the device's passwords strong. |
| 33 | string-detect | 10 | Suspicious text in traffic | The traffic contains text often linked to attacks. On its own this is usually low risk. No action is needed unless it keeps happening. |
| 34 | successful-user | 8 | Someone may have gotten into a device | The traffic suggests someone may have gotten into a device. Check the device right away and change its passwords. |
| 35 | default-login-attempt | 5 | Sign-in attempt with a device's original password | Someone tried to sign in using the password a device came with when it was bought. Change these passwords on all your devices. |
| 36 | successful-recon-largescale | 2 | Device revealed information useful to attackers | A device shared information that attackers can use, such as an old software version or stored records. Update the device's software. |
| 37 | non-standard-protocol | 2 | Non-standard connection | A device communicated in a non-standard way. This is usually harmless. No action is needed unless it keeps happening. |
| 38 | unusual-client-port-connection | 1 | Connection on an uncommon channel | A device connected through an uncommon channel that some harmful software uses to hide. Check this device if you do not recognize this activity. |
| 39 | system-call-detect | 1 | Suspicious command in traffic | The traffic contains a command often used in attacks to take over a device. Make sure the device's software is updated. |
| - | (no classtype, or a classtype not listed above; includes the ASSAS TEST rules) | - | Network activity detected | Assas noticed traffic that matched one of its security rules ({rule}). The full rule details are below. |

## Rule-specific messages
These rules get their own title and explanation instead of their classtype text; the original rule name still shows in the alert details. The SIDs are only the lookup key and are never shown to the user.

| SIDs | Title (alert list) | Explanation (alert details) |
|---|---|---|
| 2100498, 2019284 | Possible remote control of a device | A device sent back a reply that often appears when someone is running commands on it from another place. Check the device right away and change its passwords. |
| 2002023, 2002024, 2002025, 2002027, 2002028, 2000355, 2000345 | Connection to an old chat system | A device connected to an old chat system that people rarely use today. Harmful software on smart devices often uses it to receive commands. If this is a smart device, restart it, update it and change its password. |
| 2019240, 2032973 | Program file for smart devices downloaded | A device downloaded a program file made for devices like cameras and routers. Harmful software often spreads to smart devices this way. If you did not install anything, restart the device, update it and change its password. |
| 2038656, 2032924, 2025126, 2025123, 2025125, 2038657 | Request for a program built for smart devices | A device asked for program files built for smart devices, such as cameras and routers. This is a common sign of an attempt to infect a smart device. Restart the device, update it and change its password. |
| 2003068 | Device trying to reach many other devices | A device tried to reach the remote sign-in feature of many other devices. Infected smart devices do this to spread. If this device started it, restart it, update it and change its password. |
| 2010935, 2010937 | Attempt to reach a device's database feature | Someone tried to reach a database feature on a device. Scans do this to find weak devices. If you did not run a security scan, check the device. |

2100498 is also the detection self-test, so its alerts show "Possible remote control of a device".

## Team decisions (2026-11-14)
1. Language: English only, same as the app interface.
2. Rules with no classtype, including the test rules, use the fallback title. Their original rule name stays in the details. *(Release 1: the fallback title is now "Network activity detected", the explanation names the rule, and the test rules are ASSAS TEST High/Medium/Low; see below.)*
3. policy-violation keeps its top severity (priority 1). Its title is "Unsafe activity" (not "not an attack", so the title does not contradict the badge). *(Release 1: priority 1 is now High, not Critical. Text review 2026-11-22: the title is "Activity many networks block", and the explanation says "This is not always an attack, but it can put privacy or security at risk." instead of "It is not an attack.", so the text still does not contradict the High badge.)*
4. Each title and explanation is reviewed by at least one more team member before release (titles must not understate or overstate the risk).

## Release 1 changes
- **Chosen by the Suricata category.** The ingester stores Suricata's category text and maps it to the short classtype through `classification.config`; the table above is looked up by that classtype when an alert is read, so a wording change applies to every alert. A rule listed under *Rule-specific messages* uses that text instead (looked up by the stored rule ID).
- **Severity.** Priority 1 → High, 2 → Medium, 3 or more (or missing) → Low. There is no Critical.
- **Fallback.** No classtype, or one not in the table: title "Network activity detected", and the explanation names the original rule (`{rule}` in the table row is filled with `"<rule name>"`), e.g. Assas noticed traffic that matched one of its security rules ("ASSAS TEST High"). The full rule details are below.
- **Device and time.** The app shows "{device} · {first detection time}" under the title; for unlinked alerts it shows "Unknown device · {time}". This line is not part of the stored text.
- **Original rule.** The original rule name is always shown in the alert details, even when there is a plain title.
- **Rule ID.** Team decision: the rule ID is never shown to the user, neither in the details nor in any title or explanation. It stays in the API response (`rule_id`) for internal use.
- **Test rules.** ASSAS TEST High (SID 1000001, priority 1), Medium (1000002, priority 2) and Low (1000003, priority 3). SID 1000004 is retired. None has a classtype, so all three use the fallback.
