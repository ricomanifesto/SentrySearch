from pathlib import Path

import pytest
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCKUP_PATHS = (
    REPO_ROOT / "docs" / "assets" / "logo-lockup-light.png",
    REPO_ROOT / "docs" / "assets" / "logo-lockup-dark.png",
)


@pytest.mark.parametrize("lockup_path", LOCKUP_PATHS)
def test_readme_lockup_has_balanced_transparent_margins(lockup_path: Path):
    with Image.open(lockup_path).convert("RGBA") as lockup:
        bounds = lockup.getchannel("A").getbbox()

        assert bounds is not None
        left, top, right, bottom = bounds
        assert abs(left - (lockup.width - right)) <= 1
        assert abs(top - (lockup.height - bottom)) <= 2


def test_readme_preserves_lockup_display_size_after_crop():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert 'alt="SentrySearch" width="341"' in readme
