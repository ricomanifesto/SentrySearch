"""Product-side ownership carried by a runtime generation attempt."""

from dataclasses import dataclass
import uuid

EVALUATION_LEASE_SECONDS = 900


class GenerationLeaseLost(RuntimeError):
    """The report is terminal, deleted, or owned by a newer generation attempt."""


@dataclass(frozen=True)
class GenerationLease:
    run_id: str
    owner: str
    version: int

    def __post_init__(self) -> None:
        uuid.UUID(self.run_id)
        if not self.owner.strip() or self.version < 1:
            raise ValueError("generation lease requires an owner and positive version")
