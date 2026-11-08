"""The production IP indicator rule agrees with the Lean specification's case table."""

from pathlib import Path
import re

import pytest

from src.core.evidence_admissibility import _classify_indicator

CASES = Path(__file__).resolve().parents[1] / "formal" / "SentrySearchSpec" / "IpCases.lean"
RULE_IDS = {
    "invalid": "indicator.ip-invalid",
    "documentation": "indicator.ip-documentation",
    "specialUse": "indicator.ip-special-use",
    "privateContext": "indicator.ip-private-context",
    "nonGlobal": "indicator.ip-non-global",
    "publicAddress": "indicator.ip-public",
}


def _cases() -> list[tuple[str, str]]:
    found = re.findall(r'^\s*entry "([^"]+)" .*\.(\w+),?\s*$', CASES.read_text(), re.MULTILINE)
    assert len(found) >= 10, "the Lean case table could not be read"
    return found


@pytest.mark.parametrize("value,verdict", _cases())
def test_production_rule_matches_the_lean_case_table(value, verdict):
    assert _classify_indicator("ips", value)[2] == RULE_IDS[verdict]
