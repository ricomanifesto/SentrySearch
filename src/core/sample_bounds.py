"""Distribution-free sample-size bounds for bounded scores."""

from __future__ import annotations

import math
from typing import Literal

Sidedness = Literal["one", "two"]


def half_width(n: int, delta: float, *, sided: Sidedness = "two") -> float:
    """Return the Hoeffding half-width for a mean of ``n`` values in [0, 1].

    With probability at least ``1 - delta`` the sample mean lies within the
    returned distance of the true mean (on one side for ``sided="one"``).
    Rescale by the score range to express the width in native units.
    """

    if n < 1:
        raise ValueError("n must be at least 1")
    if not 0 < delta < 1:
        raise ValueError("delta must be strictly between 0 and 1")
    if sided == "two":
        tail = 2 / delta
    elif sided == "one":
        tail = 1 / delta
    else:
        raise ValueError("sided must be 'one' or 'two'")
    return math.sqrt(math.log(tail) / (2 * n))
