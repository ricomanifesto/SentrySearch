import math
from typing import Any, cast

import pytest

from src.core.sample_bounds import half_width


@pytest.mark.parametrize(
    ("n", "expected"),
    [(20, 0.304), (50, 0.192), (185, 0.100), (600, 0.055)],
)
def test_two_sided_half_width_matches_hoeffding_pins(n, expected):
    assert half_width(n, 0.05) == pytest.approx(expected, abs=0.001)


def test_one_sided_half_width_is_narrower_than_two_sided():
    assert half_width(600, 0.05, sided="one") == pytest.approx(0.050, abs=0.001)
    assert half_width(600, 0.05, sided="one") < half_width(600, 0.05)


def test_half_width_shrinks_with_sample_size():
    widths = [half_width(n, 0.05) for n in (1, 20, 50, 185, 600)]
    assert widths == sorted(widths, reverse=True)
    assert half_width(1, 0.05) == pytest.approx(math.sqrt(math.log(40) / 2))


@pytest.mark.parametrize("n", [0, -1])
def test_half_width_rejects_empty_samples(n):
    with pytest.raises(ValueError):
        half_width(n, 0.05)


@pytest.mark.parametrize("delta", [0.0, 1.0, -0.1, 1.5, math.nan])
def test_half_width_rejects_delta_outside_open_unit_interval(delta):
    with pytest.raises(ValueError):
        half_width(20, delta)


def test_half_width_rejects_unknown_sidedness():
    with pytest.raises(ValueError):
        half_width(20, 0.05, sided=cast(Any, "both"))
