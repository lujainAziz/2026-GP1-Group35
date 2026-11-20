# Threat Alert titles and explanations

Source: Sprint 2 decision (2026-11-11): Option 2, updated by the Release 1 decisions
(see *Release 1 changes* at the end). The title in the alert list is a short plain-language name based on the rule classification (classtype). The original Suricata rule name stays visible in the alert details. Titles must be clear and must accurately reflect the detected threat.

Classtypes below are the 39 that appear in the enabled rules on the device (counted 2026-11-14), ordered by number of enabled rules.

Writing rules used for this draft:
- The title says what was seen, not more. Words like "may", "possible" or "attempt" are used when the rule cannot prove the result.
- The explanation has two parts: what it means, and what the user can do.
- No title claims a device is infected unless the classtype says the activity was detected (not just attempted).
- Plain words instead of technical terms (no "domain", "exploit kit", "protocol" in titles).
- Low-concern groups say so in the title ("usually harmless"), so similar-looking titles are not confused.

## Device role line (agreed 2026-11-14)
An alert is linked to one device, but that device can be the one that started the activity or the one that was targeted (example: the Norton scan was linked to the laptop that did the scanning). The title stays neutral, and the alert details add one line from the stored source and destination:
- "This device started the activity." (the device is the source)
- "This device was the target." (the device is the destination)
The explanation is written so it reads correctly with either line.

| # | classtype | Enabled rules | Title (alert list) | Explanation (alert details) |
|---|---|---|---|---|
| 1 | trojan-activity | 10,173 | Malware activity | Traffic from or to this device matches a known pattern of malicious software. The device may be infected. Check it with a security scanner and update its software. |
| 2 | bad-unknown | 7,426 | Suspicious traffic | Traffic looks suspicious but is not linked to a specific known threat. It can also come from normal apps. Watch whether it repeats on this device. |
| 3 | domain-c2 | 7,216 | Contact with a known malware server | A device looked up or contacted a server address known to be used to control malware. The device that made the request may be infected, or a bad link was opened. Check that device with a security scanner. |
| 4 | web-application-attack | 6,017 | Web attack attempt | A request tried to attack a website or web service, for example by injecting commands. If the target is a device in your home, make sure its software is up to date. |
| 5 | misc-activity | 4,684 | Notable activity (usually harmless) | Activity that is not normally harmful but is worth noting. Usually no action is needed unless it repeats often. |
| 6 | command-and-control | 3,626 | Malware communicating with its controller | The traffic matches how malware talks to the server that controls it. The device that started this traffic is likely infected. Disconnect it if possible and check it with a security scanner. |
| 7 | exploit-kit | 2,687 | Attempt to break in through software flaws | Traffic matches tools that try to break into a device through weaknesses in its browser or software. Update the device's browser and software. |
| 8 | attempted-admin | 2,043 | Attempt to take admin control | Someone tried to gain administrator control of a device or service. Check that the target uses strong passwords and up-to-date software. |
| 9 | social-engineering | 1,551 | Possible scam or phishing | Traffic matches content that tries to trick users, such as fake login pages or scam sites. Do not enter passwords on such pages. |
| 10 | credential-theft | 1,548 | Possible password theft | Traffic matches pages or tools used to steal usernames and passwords. If a password was entered, change it. |
| 11 | misc-attack | 1,323 | Attack attempt | Traffic matches a known attack that does not fit a more specific group. Check that the target device is up to date. |
| 12 | targeted-activity | 978 | Targeted attack activity | Traffic matches tools used in planned attacks against specific targets. Check the device with a security scanner. |
| 13 | attempted-user | 830 | Attempt to gain access to a device | Someone tried to gain user-level access to a device or service. Check the target's passwords and updates. |
| 14 | pup-activity | 667 | Unwanted software activity | Traffic matches software that is often unwanted, such as adware or toolbars. Review the apps installed on the device that started this activity. |
| 15 | protocol-command-decode | 618 | Unusual communication pattern | Devices communicated in an unusual way. Often harmless, but can be part of an attack. |
| 16 | policy-violation | 543 | Unsafe activity | Activity that puts privacy or security at serious risk, such as sending a password without encryption or using anonymity networks. It is not always an attack, but it should not happen without a reason. Check whether this activity is expected on this device. |
| 17 | attempted-recon | 279 | Information gathering attempt | Someone tried to collect information about a device or service, often the first step before an attack. |
| 18 | web-application-activity | 165 | Access to a vulnerable web application | A device accessed a web application known to have weaknesses. Make sure it is updated. |
| 19 | external-ip-check | 146 | Device checked its public IP address | A device asked an online service for your home's public IP address. Many apps do this, but malware does too. Check the device only if it is unknown or acts strangely. |
| 20 | unknown | 136 | Unclassified activity (usually harmless) | Traffic that the rules could not classify. Usually no action is needed. |
| 21 | attempted-dos | 97 | Attempt to overload a service | Traffic tried to make a device or service stop responding by overloading it. |
| 22 | not-suspicious | 76 | Informational event | Traffic recorded for information only; it is not considered suspicious. |
| 23 | shellcode-detect | 62 | Malicious code in traffic | Traffic contains code that attacks use to take control of a program. Check the target device and update its software. |
| 24 | rpc-portmap-decode | 60 | Request listing a device's services | A device was asked which services it offers. Normal in some networks, but also used before attacks. |
| 25 | coin-mining | 56 | Cryptocurrency mining activity | Traffic matches cryptocurrency mining. If you did not set this up on the device that started it, that device may be infected. |
| 26 | successful-admin | 53 | Admin control may have been gained | Traffic suggests an attacker gained administrator control of a device or service. Check the device right away and change its passwords. |
| 27 | suspicious-filename-detect | 26 | Suspicious file name | A file with a name commonly used by malware was transferred. Do not open the file. |
| 28 | successful-recon-limited | 21 | Information may have leaked | A device may have revealed information about itself or its configuration. |
| 29 | network-scan | 21 | Network scan | A device scanned the network to find other devices and open services. Check whether this scan was expected. |
| 30 | denial-of-service | 16 | Attack to stop a service from working | Traffic matches an attack that tries to stop a device or service from working. |
| 31 | suspicious-login | 14 | Suspicious login attempt | Someone tried to log in with a suspicious username. Check the target's passwords. |
| 32 | unsuccessful-user | 12 | Failed attempt to gain access | Someone tried to gain access to a device or service and failed. Keep passwords strong. |
| 33 | string-detect | 10 | Suspicious text in traffic | Traffic contains text often linked to attacks. Usually low risk on its own. |
| 34 | successful-user | 8 | Access to a device may have been gained | Traffic suggests an attacker gained user-level access to a device. Check the device and change its passwords. |
| 35 | default-login-attempt | 5 | Login attempt with a default password | Someone tried to log in using a factory default username and password. Change default passwords on all devices. |
| 36 | successful-recon-largescale | 2 | Large information leak possible | A device may have revealed a large amount of information about itself. |
| 37 | non-standard-protocol | 2 | Non-standard communication | A device communicated in a way that is not standard. |
| 38 | unusual-client-port-connection | 1 | Connection on an unusual port | A device connected using an unusual port, which some malware does to avoid detection. |
| 39 | system-call-detect | 1 | Suspicious system command | Traffic contains a system command often used in attacks. |
| - | (no classtype, or a classtype not listed above; includes the four ASSAS TEST rules) | - | Network activity detected | Assas detected network traffic that matched a security rule ({rule}). The original rule details are shown below. |

## Team decisions (2026-11-14)
1. Language: English only, same as the app interface.
2. Rules with no classtype, including the test rules, use the fallback title. Their original rule name stays in the details. *(Release 1: the fallback title is now "Network activity detected", the explanation names the rule, and the test rules are ASSAS TEST High/Medium/Low; see below.)*
3. policy-violation keeps its top severity (priority 1). Its title is "Unsafe activity" (not "not an attack", so the title does not contradict the badge). *(Release 1: priority 1 is now High, not Critical.)*
4. Each title and explanation is reviewed by at least one more team member before release (titles must not understate or overstate the risk).

## Release 1 changes
- **Chosen by the Suricata category.** The ingester stores Suricata's category text and maps it to the short classtype through `classification.config`; the table above is looked up by that classtype when an alert is read, so a wording change applies to every alert.
- **Severity.** Priority 1 → High, 2 → Medium, 3 or more (or missing) → Low. There is no Critical.
- **Fallback.** No classtype, or one not in the table: title "Network activity detected", and the explanation names the original rule and its rule ID (`{rule}` in the table row is filled with `"<rule name>", rule ID <SID>`).
- **Device and time.** The app shows "{device} · {first detection time}" under the title; for unlinked alerts it shows "Unknown device · {time}". This line is not part of the stored text.
- **Original rule.** The original rule name and rule ID are always shown in the alert details, even when there is a plain title.
- **Test rules.** ASSAS TEST High (SID 1000001, priority 1), Medium (1000002, priority 2) and Low (1000003, priority 3). SID 1000004 is retired. None has a classtype, so all three use the fallback.
