"""Report category and threat-type classification as one data table.

Two inputs are classified: the structured ``coreMetadata.category`` text a
profile records, and, as a fallback, the free-text tool name. Each input has one
ordered rule table and one function that reads it. The first matching rule wins.
"""

from __future__ import annotations

from typing import Iterable

Classification = tuple[str, str]

# Structured profile category text. A marker matches anywhere in the category
# with a leading space prepended, so `` rat`` matches "RAT" but not "Pirate".
CATEGORY_RULES: tuple[tuple[tuple[str, ...], Classification], ...] = (
    (("remote access", " rat"), ("malware", "remote_access_trojan")),
    (
        ("post-exploitation", "post exploitation", "framework"),
        ("malware", "post_exploitation_framework"),
    ),
    (("ransomware",), ("malware", "ransomware")),
    (("backdoor",), ("malware", "backdoor")),
    (("trojan",), ("malware", "trojan")),
    (("botnet",), ("malware", "botnet")),
    (("downloader", "loader"), ("malware", "loader")),
    (("apt",), ("malware", "apt_malware")),
    (("malware",), ("malware", "malware")),
    (("threat actor", "threat group"), ("threat_group", "threat_actor")),
    (("security tool",), ("legitimate_software", "security_tool")),
    (
        ("software", "technology", "platform"),
        ("legitimate_software", "legitimate_software"),
    ),
)

# Tool-name fallback. A family applies when any gate marker occurs in the
# lowercased name; its first matching refinement then decides the threat type,
# otherwise the family default applies. Families are checked in order.
TOOL_NAME_FAMILIES: tuple[
    tuple[tuple[str, ...], tuple[tuple[tuple[str, ...], Classification], ...], Classification],
    ...,
] = (
    (
        (
            "ransomware",
            "trojan",
            "backdoor",
            "rat",
            "rootkit",
            "spyware",
            "adware",
            "worm",
            "virus",
            "botnet",
            "cryptominer",
            "stealer",
            "loader",
            "dropper",
            "shadowpad",
            "cobalt strike",
            "meterpreter",
            "empire",
            "mimikatz",
            "lazarus",
            "apt",
            "carbanak",
            "emotet",
            "trickbot",
            "ryuk",
            "conti",
            "lockbit",
            "stealc",
            "bumblebee",
            "redline",
            "azorult",
            "formbook",
            "agent tesla",
            "nanocore",
            "njrat",
            "darkcomet",
            "poison ivy",
            "blackrat",
        ),
        (
            (("ransomware", "ryuk", "conti", "lockbit"), ("malware", "ransomware")),
            (("rat", "backdoor", "remote access"), ("malware", "remote_access_trojan")),
            (("trojan", "stealer", "stealc", "redline"), ("malware", "trojan")),
            (("apt", "advanced persistent"), ("malware", "apt_malware")),
            (("botnet", "bot"), ("malware", "botnet")),
            (
                ("framework", "cobalt", "empire", "meterpreter"),
                ("malware", "post_exploitation_framework"),
            ),
        ),
        ("malware", "malware"),
    ),
    (
        (
            "lazarus",
            "apt1",
            "apt28",
            "apt29",
            "apt34",
            "apt40",
            "fancy bear",
            "cozy bear",
            "carbanak",
            "fin7",
            "fin8",
            "wizard spider",
            "sandworm",
            "turla",
            "equation group",
            "darkhydrus",
            "mustang panda",
            "kimsuky",
        ),
        (),
        ("threat_group", "threat_actor"),
    ),
    (
        (
            "windows",
            "microsoft",
            "office",
            "outlook",
            "excel",
            "word",
            "powershell",
            "cmd",
            "notepad",
            "explorer",
            "chrome",
            "firefox",
            "safari",
            "adobe",
            "java",
            "python",
            "nodejs",
            "git",
            "docker",
            "kubernetes",
            "jenkins",
            "sharepoint",
            "exchange",
            "active directory",
            "ldap",
            "ssh",
            "ftp",
            "sftp",
            "vmware",
            "virtualbox",
            "hyper-v",
            "citrix",
            "remote desktop",
            "vnc",
            "teamviewer",
            "anydesk",
            "logmein",
            "webex",
            "zoom",
            "slack",
            "teams",
            "sap",
            "oracle",
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            "elasticsearch",
            "apache",
            "nginx",
            "iis",
            "tomcat",
            "node",
            "express",
            "react",
            "angular",
            "get-aduser",
            "nltest",
            "net user",
            "whoami",
            "ipconfig",
            "netstat",
            "ping",
            "tracert",
            "nslookup",
            "runas",
            "tasklist",
            "services",
        ),
        (
            (
                ("windows", "cmd", "powershell", "net ", "runas", "nltest", "get-aduser"),
                ("legitimate_software", "system_administration"),
            ),
            (
                ("office", "word", "excel", "outlook", "sharepoint"),
                ("legitimate_software", "productivity_software"),
            ),
            (("chrome", "firefox", "safari", "browser"), ("legitimate_software", "web_browser")),
            (
                ("ssh", "ftp", "remote", "vnc", "teamviewer", "anydesk"),
                ("legitimate_software", "remote_access"),
            ),
            (
                ("vmware", "docker", "kubernetes", "virtualization"),
                ("legitimate_software", "virtualization"),
            ),
            (("apache", "nginx", "iis", "server"), ("legitimate_software", "server_software")),
        ),
        ("legitimate_software", "legitimate_software"),
    ),
)


def _first_match(
    text: str, rules: Iterable[tuple[tuple[str, ...], Classification]]
) -> Classification | None:
    for markers, classification in rules:
        if any(marker in text for marker in markers):
            return classification
    return None


def classify_category_text(category: str | None) -> Classification | None:
    """Map a structured profile category to (category, threat_type)."""

    if not category:
        return None
    return _first_match(f" {category.lower()}", CATEGORY_RULES)


def classify_tool_name(tool_name: str | None) -> Classification | None:
    """Map a free-text tool name to (category, threat_type) by family."""

    name = (tool_name or "").lower().strip()
    if not name:
        return None
    for gate_markers, refinements, default in TOOL_NAME_FAMILIES:
        if any(marker in name for marker in gate_markers):
            return _first_match(name, refinements) or default
    return None
