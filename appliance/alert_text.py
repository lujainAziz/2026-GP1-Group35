"""Plain-language Threat Alert titles and explanations, per Suricata classtype,
with rule-specific text for a few SIDs.

Source of truth: docs/sprint-2/threat-alert-titles.md (reviewed per team
decision 4). test_alert_text.py checks both tables against that document row
for row, so a wording change is made in both places or the tests fail.

The text is looked up when an alert is read (API), never stored on the alert:
a reviewed wording change applies to every alert without a data migration.
English only (team decision 1).
"""

# classtype -> (title shown in the alert list, explanation shown in the details)
CLASSTYPE_TEXT = {
    "trojan-activity": (
        "Possible harmful software",
        "This traffic matches the behavior of known harmful software. A device may be infected. Run an antivirus scan on it and keep its apps updated.",
    ),
    "bad-unknown": (
        "Suspicious traffic",
        "A device used a website or service that attackers sometimes use, but normal apps use it too. No action is needed unless it keeps happening.",
    ),
    "domain-c2": (
        "Contact with a known harmful server",
        "A device tried to reach an internet address known to control harmful software. This can happen after clicking a bad link, or if the device is infected. Run an antivirus scan on it.",
    ),
    "web-application-attack": (
        "Attempt to attack a website",
        "Someone sent a request that tries to break into a website or a device's settings page. If this device was the target, update its software. If it sent the request, run an antivirus scan on it.",
    ),
    "misc-activity": (
        "Notable activity (often harmless)",
        "This activity is often harmless but worth knowing about. No action is needed unless it keeps happening or you do not recognize it.",
    ),
    "command-and-control": (
        "Harmful software contacting its controller",
        "This traffic matches how harmful software talks to the computer that controls it. The device is likely infected. Disconnect it from the network if you can, and run an antivirus scan.",
    ),
    "exploit-kit": (
        "Contact with a site that attacks devices",
        "A device tried to reach a website linked to tools that break into devices through old browsers or apps. Update the device's browser and apps.",
    ),
    "attempted-admin": (
        "Attempt to take full control of a device",
        "Someone tried to get full control of a device or one of its features. Make sure the device uses a strong password and updated software.",
    ),
    "social-engineering": (
        "Possible scam website",
        "A device opened, or tried to open, a page that may be a scam, such as a fake sign-in page. Do not enter passwords or payment details on pages you do not trust.",
    ),
    "credential-theft": (
        "Possible password theft",
        "Someone using a device may have typed information into a fake page used to steal passwords. If you typed a password there, change it right away.",
    ),
    "misc-attack": (
        "Contact with a risky internet address",
        "A device exchanged traffic with an internet address that security lists mark as risky. This is not always an attack. Watch whether it keeps happening.",
    ),
    "targeted-activity": (
        "Contact linked to a hacking group",
        "A device tried to reach an address linked to organized hacking groups. Run an antivirus scan on it.",
    ),
    "attempted-user": (
        "Attempt to get into a device",
        "Someone tried to get into a device or one of its features. Make sure it uses a strong password and updated software.",
    ),
    "pup-activity": (
        "Unwanted app activity",
        "This traffic matches apps that are often unwanted, such as apps that show ads or browser add-ons. Check the apps installed on the device and remove ones you do not need.",
    ),
    "protocol-command-decode": (
        "Irregular network messages",
        "A device sent or received network messages that did not follow the expected format. This is usually harmless, but it can be part of an attack. No action is needed unless it keeps happening.",
    ),
    "policy-violation": (
        "Risky or restricted activity",
        "A device did something that many networks do not allow, such as using file-sharing, chat or game apps, or sending passwords or other private information in a way others could read. This is not always an attack, but it can put privacy or security at risk. Check that it is expected on this device.",
    ),
    "attempted-recon": (
        "Attempt to learn about a device",
        "Someone tried to learn about a device, such as what it runs. This is often an early step before an attack. Make sure the device's software is updated.",
    ),
    "web-application-activity": (
        "Use of a website with known weaknesses",
        "A device used a website or web page that has known security weaknesses. If the page belongs to this device, update its software.",
    ),
    "external-ip-check": (
        "Device checked your internet address",
        "A device asked an online service for your home's internet address. Many apps do this, but harmful software does too. Check the device only if you do not recognize it or it acts strangely.",
    ),
    "unknown": (
        "Unclassified activity",
        "This traffic matched a security rule that has no specific group. It is often harmless, but some of these rules look for signs of harmful software. Watch whether it keeps happening.",
    ),
    "attempted-dos": (
        "Attempt to overload a device",
        "There was an attempt to stop a device from working by flooding it with requests. If this device was the target and stopped responding, restart it.",
    ),
    "not-suspicious": (
        "Normal activity (for your information)",
        "This activity was recorded for information only. It is not considered suspicious. No action is needed.",
    ),
    "shellcode-detect": (
        "Possible attack code",
        "The traffic contains code that attacks often use to take over apps. Make sure the device's software is updated.",
    ),
    "rpc-portmap-decode": (
        "Request to list what a device offers",
        "A device was asked what network features it offers. This is normal on some networks, but attackers also do it before an attack. No action is needed unless it keeps happening.",
    ),
    "coin-mining": (
        "Cryptocurrency mining activity",
        "This traffic matches cryptocurrency mining, which uses a device's power to earn digital money. If you did not set this up, the device may be infected. Run an antivirus scan on it.",
    ),
    "successful-admin": (
        "Someone may have taken full control of a device",
        "The traffic suggests someone may have gained full control of a device. Check the device right away and change its passwords.",
    ),
    "suspicious-filename-detect": (
        "Request for a suspicious file",
        "A device asked for a file whose name is often used by harmful or password-stealing software. Do not run or install such files unless you expected them.",
    ),
    "successful-recon-limited": (
        "Device may have shared private information",
        "A device may have shared information about itself, such as its settings or user accounts. Make sure the device's software is updated.",
    ),
    "network-scan": (
        "Network scan",
        "A device searched the network to find other devices and what they offer. This is fine if you or an app you trust started it. Otherwise, check the device.",
    ),
    "denial-of-service": (
        "Possible attack to stop a device",
        "The traffic matches attacks that try to stop a device from working. If this device was the target and stopped responding, restart it and update its software.",
    ),
    "suspicious-login": (
        "Suspicious sign-in activity",
        "The traffic matches suspicious sign-in attempts or tools used to steal passwords. Make sure the device uses strong passwords.",
    ),
    "unsuccessful-user": (
        "Failed attempt to get into a device",
        "Someone tried to get into a device and failed. Keep the device's passwords strong.",
    ),
    "string-detect": (
        "Suspicious text in traffic",
        "The traffic contains text often linked to attacks. On its own this is usually low risk. No action is needed unless it keeps happening.",
    ),
    "successful-user": (
        "Someone may have gotten into a device",
        "The traffic suggests someone may have gotten into a device. Check the device right away and change its passwords.",
    ),
    "default-login-attempt": (
        "Sign-in attempt with a device's original password",
        "Someone tried to sign in using the password a device came with when it was bought. Change the original passwords on all your devices.",
    ),
    "successful-recon-largescale": (
        "Device revealed information useful to attackers",
        "A device shared information that attackers can use, such as which old software version it runs or data it has saved. Update the device's software.",
    ),
    "non-standard-protocol": (
        "Connection in an unexpected format",
        "A device connected in a way that does not follow the usual rules for that kind of connection. This is usually harmless. No action is needed unless it keeps happening.",
    ),
    "unusual-client-port-connection": (
        "Connection made in an uncommon way",
        "A device connected in a way that normal apps rarely use. Some harmful software connects this way to hide. Check this device if you do not recognize this activity.",
    ),
    "system-call-detect": (
        "Suspicious command in traffic",
        "The traffic contains a command often used in attacks to take over a device. Make sure the device's software is updated.",
    ),
}

# Rule-specific text: overrides the classtype text for these SIDs. Each group
# shares one (title, explanation); the original rule name stays in the details.
# The SIDs are only the lookup key and are never shown to the user.
RULE_GROUPS = (
    ((2100498, 2019284), (
        "Possible remote control of a device",
        "A device sent back a reply that often appears when someone is running commands on it from another computer. Check the device right away and change its passwords.",
    )),
    ((2002023, 2002024, 2002025, 2002027, 2002028, 2000355, 2000345), (
        "Connection to an old chat system",
        "A device connected to an old chat system that people rarely use today. Harmful software on smart devices often uses it to receive commands. If this is a smart device, restart it, update it and change its password.",
    )),
    ((2019240, 2032973), (
        "Smart-device program downloaded",
        "A device downloaded a program file made for devices like cameras and routers. Harmful software often spreads to smart devices this way. If you did not install anything, restart the device, update it and change its password.",
    )),
    ((2038656, 2032924, 2025126, 2025123, 2025125, 2038657), (
        "Request for a program built for smart devices",
        "A device asked for a program file built for smart devices, such as cameras and routers. This is a common sign of an attempt to infect a smart device. Restart the device, update it and change its password.",
    )),
    ((2003068,), (
        "Device trying to reach many other devices",
        "A device tried to reach the remote sign-in feature of many other devices. Infected smart devices do this to spread. If this device started it, restart it, update it and change its password.",
    )),
    ((2010935, 2010937), (
        "Attempt to reach a device's database feature",
        "Someone tried to reach a database feature on a device. Scans do this to find weak devices. If you did not run a security scan, check the device.",
    )),
)

# SID -> (title, explanation)
RULE_TEXT = {sid: text for sids, text in RULE_GROUPS for sid in sids}

# No classtype, or a classtype not listed above (includes the ASSAS TEST rules).
# {rule} is filled with the original rule name. The rule ID is never shown to
# the user (team decision); it stays in the API response for internal use.
FALLBACK_TEXT = (
    "Network activity detected",
    "Assas noticed traffic that matched one of its security rules ({rule}). The full rule details are below.",
)


def rule_info(rule_name=None):
    """The original rule as shown in the fallback text: '"<name>"'."""
    name = rule_name.strip() if isinstance(rule_name, str) else ""
    return f'"{name}"' if name else "no rule details available"


def _sid(rule_id):
    """The stored rule ID as an int, or None when missing or not a number."""
    if isinstance(rule_id, bool):
        return None
    if isinstance(rule_id, int):
        return rule_id
    if isinstance(rule_id, str) and rule_id.strip().isdigit():
        return int(rule_id.strip())
    return None


def alert_text(classtype, rule_name=None, rule_id=None):
    """(title, explanation): the rule-specific text for a listed SID, else the
    text for the stored classtype, else the fallback."""
    sid = _sid(rule_id)
    if sid in RULE_TEXT:
        return RULE_TEXT[sid]
    if isinstance(classtype, str) and classtype.strip() in CLASSTYPE_TEXT:
        return CLASSTYPE_TEXT[classtype.strip()]
    title, explanation = FALLBACK_TEXT
    return title, explanation.format(rule=rule_info(rule_name))
