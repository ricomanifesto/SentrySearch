"""Category and tool-name classification read one ordered rule table each."""

import pytest

from src.domain.threat_classification import classify_category_text, classify_tool_name
from src.storage.report_service import ReportStorageService


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("Remote Access Trojan", ("malware", "remote_access_trojan")),
        ("RAT", ("malware", "remote_access_trojan")),
        ("Pirate kit", None),
        ("Post-Exploitation Framework", ("malware", "post_exploitation_framework")),
        ("Ransomware", ("malware", "ransomware")),
        ("Loader", ("malware", "loader")),
        ("Threat Group", ("threat_group", "threat_actor")),
        ("Security Tool", ("legitimate_software", "security_tool")),
        ("Cloud platform", ("legitimate_software", "legitimate_software")),
        ("", None),
        (None, None),
    ],
)
def test_category_rules(category, expected):
    assert classify_category_text(category) == expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("LockBit 3.0", ("malware", "ransomware")),
        ("NjRAT", ("malware", "remote_access_trojan")),
        ("RedLine Stealer", ("malware", "trojan")),
        ("Cobalt Strike", ("malware", "post_exploitation_framework")),
        ("Emotet", ("malware", "malware")),
        ("APT29", ("malware", "apt_malware")),
        ("Wizard Spider", ("threat_group", "threat_actor")),
        ("PowerShell", ("legitimate_software", "system_administration")),
        ("Microsoft Excel", ("legitimate_software", "productivity_software")),
        ("AnyDesk", ("legitimate_software", "remote_access")),
        ("Docker", ("legitimate_software", "virtualization")),
        ("nginx", ("legitimate_software", "server_software")),
        ("Zoom", ("legitimate_software", "legitimate_software")),
        ("Unheard Of Name", None),
        ("   ", None),
    ],
)
def test_tool_name_families(tool_name, expected):
    assert classify_tool_name(tool_name) == expected


def test_report_service_uses_structured_category_before_tool_name():
    service = ReportStorageService.__new__(ReportStorageService)

    assert service.categorize_tool(
        "Unheard Of Name", {"coreMetadata": {"category": "Backdoor"}}
    ) == ("malware", "backdoor")
    assert service.categorize_tool("Emotet", {"coreMetadata": {"category": "Unmapped"}}) == (
        "malware",
        "malware",
    )
    assert service.categorize_tool("Unheard Of Name", {"coreMetadata": {"category": "x"}}) == (
        "unknown",
        "unknown",
    )
    assert service.categorize_tool("") == ("unknown", "unknown")
