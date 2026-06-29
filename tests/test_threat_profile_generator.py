import json

import pytest

from src.core.threat_profile_generator import repair_invalid_json_escapes


def test_repair_makes_lone_invalid_escapes_parseable():
    # A model emitted Windows paths and regex fragments with bare backslashes.
    raw = r'{"path": "C:\Users\admin", "regex": "\d+\s", "note": "a\nb"}'

    with pytest.raises(json.JSONDecodeError):
        json.loads(raw)

    data = json.loads(repair_invalid_json_escapes(raw))

    assert data["path"] == r"C:\Users\admin"
    assert data["regex"] == r"\d+\s"
    assert data["note"] == "a\nb"  # a real newline; the valid \n was preserved


def test_repair_preserves_valid_escaped_backslashes():
    # "a" is a correctly escaped backslash; only "b" has a bare invalid escape.
    raw = r'{"a": "back\\slash", "b": "C:\Users"}'

    data = json.loads(repair_invalid_json_escapes(raw))

    assert data["a"] == "back\\slash"  # still a single backslash, not corrupted
    assert data["b"] == r"C:\Users"


def test_repair_is_noop_for_already_valid_escapes():
    raw = r'{"n": "a\nb", "q": "say \"hi\"", "u": "A"}'

    data = json.loads(repair_invalid_json_escapes(raw))

    assert data == {"n": "a\nb", "q": 'say "hi"', "u": "A"}
