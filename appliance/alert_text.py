"""Plain-language Threat Alert titles and explanations, per Suricata classtype.

Source of truth: docs/sprint-2/threat-alert-titles.md (reviewed per team
decision 4). test_alert_text.py checks this table against that document row
for row, so a wording change is made in both places or the tests fail.

The text is looked up when an alert is read (API), never stored on the alert:
a reviewed wording change applies to every alert without a data migration.
English only (team decision 1).
"""

# classtype -> (title shown in the alert list, explanation shown in the details)
CLASSTYPE_TEXT = {
    "trojan-activity": (
        "Malware activity",
        "Traffic from or to this device matches a known pattern of malicious software. The device may be infected. Check it with a security scanner and update its software.",
    ),
    "bad-unknown": (
        "Suspicious traffic",
        "Traffic looks suspicious but is not linked to a specific known threat. It can also come from normal apps. Watch whether it repeats on this device.",
    ),
    "domain-c2": (
        "Contact with a known malware server",
        "A device looked up or contacted a server address known to be used to control malware. The device that made the request may be infected, or a bad link was opened. Check that device with a security scanner.",
    ),
    "web-application-attack": (
        "Web attack attempt",
        "A request tried to attack a website or web service, for example by injecting commands. If the target is a device in your home, make sure its software is up to date.",
    ),
    "misc-activity": (
        "Notable activity (usually harmless)",
        "Activity that is not normally harmful but is worth noting. Usually no action is needed unless it repeats often.",
    ),
    "command-and-control": (
        "Malware communicating with its controller",
        "The traffic matches how malware talks to the server that controls it. The device that started this traffic is likely infected. Disconnect it if possible and check it with a security scanner.",
    ),
    "exploit-kit": (
        "Attempt to break in through software flaws",
        "Traffic matches tools that try to break into a device through weaknesses in its browser or software. Update the device's browser and software.",
    ),
    "attempted-admin": (
        "Attempt to take admin control",
        "Someone tried to gain administrator control of a device or service. Check that the target uses strong passwords and up-to-date software.",
    ),
    "social-engineering": (
        "Possible scam or phishing",
        "Traffic matches content that tries to trick users, such as fake login pages or scam sites. Do not enter passwords on such pages.",
    ),
    "credential-theft": (
        "Possible password theft",
        "Traffic matches pages or tools used to steal usernames and passwords. If a password was entered, change it.",
    ),
    "misc-attack": (
        "Attack attempt",
        "Traffic matches a known attack that does not fit a more specific group. Check that the target device is up to date.",
    ),
    "targeted-activity": (
        "Targeted attack activity",
        "Traffic matches tools used in planned attacks against specific targets. Check the device with a security scanner.",
    ),
    "attempted-user": (
        "Attempt to gain access to a device",
        "Someone tried to gain user-level access to a device or service. Check the target's passwords and updates.",
    ),
    "pup-activity": (
        "Unwanted software activity",
        "Traffic matches software that is often unwanted, such as adware or toolbars. Review the apps installed on the device that started this activity.",
    ),
    "protocol-command-decode": (
        "Unusual communication pattern",
        "Devices communicated in an unusual way. Often harmless, but can be part of an attack.",
    ),
    "policy-violation": (
        "Unsafe activity",
        "Activity that puts privacy or security at serious risk, such as sending a password without encryption or using anonymity networks. It is not always an attack, but it should not happen without a reason. Check whether this activity is expected on this device.",
    ),
    "attempted-recon": (
        "Information gathering attempt",
        "Someone tried to collect information about a device or service, often the first step before an attack.",
    ),
    "web-application-activity": (
        "Access to a vulnerable web application",
        "A device accessed a web application known to have weaknesses. Make sure it is updated.",
    ),
    "external-ip-check": (
        "Device checked its public IP address",
        "A device asked an online service for your home's public IP address. Many apps do this, but malware does too. Check the device only if it is unknown or acts strangely.",
    ),
    "unknown": (
        "Unclassified activity (usually harmless)",
        "Traffic that the rules could not classify. Usually no action is needed.",
    ),
    "attempted-dos": (
        "Attempt to overload a service",
        "Traffic tried to make a device or service stop responding by overloading it.",
    ),
    "not-suspicious": (
        "Informational event",
        "Traffic recorded for information only; it is not considered suspicious.",
    ),
    "shellcode-detect": (
        "Malicious code in traffic",
        "Traffic contains code that attacks use to take control of a program. Check the target device and update its software.",
    ),
    "rpc-portmap-decode": (
        "Request listing a device's services",
        "A device was asked which services it offers. Normal in some networks, but also used before attacks.",
    ),
    "coin-mining": (
        "Cryptocurrency mining activity",
        "Traffic matches cryptocurrency mining. If you did not set this up on the device that started it, that device may be infected.",
    ),
    "successful-admin": (
        "Admin control may have been gained",
        "Traffic suggests an attacker gained administrator control of a device or service. Check the device right away and change its passwords.",
    ),
    "suspicious-filename-detect": (
        "Suspicious file name",
        "A file with a name commonly used by malware was transferred. Do not open the file.",
    ),
    "successful-recon-limited": (
        "Information may have leaked",
        "A device may have revealed information about itself or its configuration.",
    ),
    "network-scan": (
        "Network scan",
        "A device scanned the network to find other devices and open services. Check whether this scan was expected.",
    ),
    "denial-of-service": (
        "Attack to stop a service from working",
        "Traffic matches an attack that tries to stop a device or service from working.",
    ),
    "suspicious-login": (
        "Suspicious login attempt",
        "Someone tried to log in with a suspicious username. Check the target's passwords.",
    ),
    "unsuccessful-user": (
        "Failed attempt to gain access",
        "Someone tried to gain access to a device or service and failed. Keep passwords strong.",
    ),
    "string-detect": (
        "Suspicious text in traffic",
        "Traffic contains text often linked to attacks. Usually low risk on its own.",
    ),
    "successful-user": (
        "Access to a device may have been gained",
        "Traffic suggests an attacker gained user-level access to a device. Check the device and change its passwords.",
    ),
    "default-login-attempt": (
        "Login attempt with a default password",
        "Someone tried to log in using a factory default username and password. Change default passwords on all devices.",
    ),
    "successful-recon-largescale": (
        "Large information leak possible",
        "A device may have revealed a large amount of information about itself.",
    ),
    "non-standard-protocol": (
        "Non-standard communication",
        "A device communicated in a way that is not standard.",
    ),
    "unusual-client-port-connection": (
        "Connection on an unusual port",
        "A device connected using an unusual port, which some malware does to avoid detection.",
    ),
    "system-call-detect": (
        "Suspicious system command",
        "Traffic contains a system command often used in attacks.",
    ),
}

# No classtype, or a classtype not listed above (includes the four ASSAS TEST
# rules; team decision 2).
FALLBACK_TEXT = (
    "Security alert",
    "Assas detected traffic that matched a security rule. See the rule name below for details.",
)


def alert_text(classtype):
    """(title, explanation) for a stored classtype; the fallback when unknown."""
    if isinstance(classtype, str):
        return CLASSTYPE_TEXT.get(classtype.strip(), FALLBACK_TEXT)
    return FALLBACK_TEXT
