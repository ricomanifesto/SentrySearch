"""Product-side ownership carried by a runtime generation attempt."""

from dataclasses import dataclass
from typing import Literal
import uuid

EVALUATION_LEASE_SECONDS = 900


class GenerationLeaseLost(RuntimeError):
    """The report is terminal, deleted, or owned by a newer generation attempt."""


# The terminal disagreements the product store records about a bound run.
Disagreement = Literal["runtime_result_missing", "runtime_failed_after_publication"]


@dataclass(frozen=True)
class RuntimeObservation:
    """What the product store did with one Runtime observation, decided inside its own
    transaction and returned only after it committed: whether the observation was
    applied, and the terminal disagreement it recorded when the product and the Runtime
    disagree about the run (``runtime_result_missing`` or
    ``runtime_failed_after_publication``). True exactly when applied."""

    applied: bool
    disagreement: Disagreement | None = None

    def __bool__(self) -> bool:
        return self.applied


@dataclass(frozen=True)
class GenerationLease:
    run_id: str
    owner: str
    version: int

    def __post_init__(self) -> None:
        uuid.UUID(self.run_id)
        if not self.owner.strip() or self.version < 1:
            raise ValueError("generation lease requires an owner and positive version")
