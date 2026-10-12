"""The canary's task-definition catalog keeps each revision as it was first registered.

No container, network or subprocess: only the catalog the canary's ECS stand-in
reads when it starts a task.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest

from tests.release_canary import rollback_document
from tests.release_canary_stack import CanaryEnvironment, RevisionConflict, TaskDefinitions
from tests.release_fakes import forward_document, manifest_document, task_definition

PRIOR_UNTIL = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 10, 13, 0, tzinfo=UTC)
FAILED_ID = "33333333-3333-4333-8333-333333333333"
ROLLBACK_ID = "44444444-4444-4444-8444-444444444444"


def revision_of(name: str, revision: int = 7) -> str:
    return task_definition(f"sentry-staging-{name}", revision)


def revised(document: dict, revision: int) -> dict:
    """The same release shape at another revision of every job, observer and service."""
    document = copy.deepcopy(document)
    specs = [job["task"] for job in document["jobs"]]
    specs += [check["task"] for check in document["operational_checks"] if "task" in check]
    specs += list(document["services"].values())
    for spec in specs:
        spec["task_definition"] = spec["task_definition"].rsplit(":", 1)[0] + f":{revision}"
    return document


def failed_upgrade(prior: dict) -> dict:
    failed = revised(forward_document(bootstrap=False), 8)
    failed["release_id"] = FAILED_ID
    failed["window"]["expires_at"] = "2026-10-10T13:00:00Z"
    failed["rollback"] = copy.deepcopy(manifest_document(rollback="compatible_release")["rollback"])
    failed["rollback"]["release_id"] = prior["release_id"]
    failed["rollback"]["services"] = copy.deepcopy(prior["services"])
    return failed


def catalog() -> tuple[TaskDefinitions, dict, dict]:
    """A deployed first release and a failed upgrade, each registered once."""
    # Only an observer's container is ever materialized here; nothing runs it.
    env = SimpleNamespace(material={"runtime-observer": "unused-volume"},
                          images=SimpleNamespace(tools="unused-image"))  # fmt: skip
    definitions = TaskDefinitions(cast(CanaryEnvironment, env))
    prior = forward_document()
    prior["window"]["expires_at"] = "2026-10-10T12:00:00Z"
    definitions.register(prior, not_after=PRIOR_UNTIL)
    failed = failed_upgrade(prior)
    definitions.register(failed, not_after=LATER)
    return definitions, prior, failed


def retained(document: dict) -> list[str]:
    """The retained revisions a rollback run launches: reconcile, proof and observers."""
    return [job["task"]["task_definition"] for job in document["jobs"]] + [
        check["task"]["task_definition"]
        for check in document["operational_checks"]
        if "task" in check
    ]


def test_a_release_registers_every_revision_its_plan_creates_under_one_deadline():
    definitions, prior, _failed = catalog()
    jobs = {arn: data for arn, (kind, data) in definitions.specs.items() if kind == "job"}
    # The plan defines reconcile jobs for every release, though a forward manifest
    # names none: a later rollback run finds them already there.
    for database in ("runtime", "product"):
        for revision in (7, 8):
            reconcile = jobs[revision_of(f"{database}-reconcile", revision)]
            assert reconcile["job"] == {"id": f"{database}-reconcile", "phase": "reconcile",
                                        "database": database}  # fmt: skip
    seven = {arn: data for arn, data in jobs.items() if arn.endswith(":7")}
    assert {data["job"]["phase"] for data in seven.values()} == {
        "bootstrap", "migrate", "grant", "proof", "reconcile"
    }  # fmt: skip
    assert {data["not_after"] for data in seven.values()} == {PRIOR_UNTIL}
    assert {data["release_id"] for data in seven.values()} == {prior["release_id"]}
    eight = {arn: data for arn, data in jobs.items() if arn.endswith(":8")}
    assert {data["not_after"] for data in eight.values()} == {LATER}


def test_a_rollback_run_launches_retained_revisions_with_their_original_deadline():
    definitions, prior, failed = catalog()
    before = copy.deepcopy(definitions.specs)
    rollback = rollback_document(prior, failed, release_id=ROLLBACK_ID)
    assert rollback["window"]["expires_at"] == "2026-10-10T13:00:00Z"
    definitions.require_retained(rollback)
    assert definitions.specs == before
    for arn in retained(rollback):
        kind, data = definitions.specs[arn]
        assert arn.endswith(":7") and data["not_after"] == PRIOR_UNTIL, arn
        assert data["release_id"] == prior["release_id"]
    observer = revision_of("runtime-observe")
    environment = definitions.spec(observer, "a" * 32).environment
    assert environment["RELEASE_NOT_AFTER"] == "2026-10-10T12:00:00Z"
    assert environment["RELEASE_ID"] == prior["release_id"]


def test_registering_an_existing_revision_differently_is_refused():
    definitions, prior, failed = catalog()
    before = copy.deepcopy(definitions.specs)
    rollback = rollback_document(prior, failed, release_id=ROLLBACK_ID)
    # What the canary used to do: register the rollback run's revisions under its
    # own, later window, rewriting the retained revisions' deadline in place.
    with pytest.raises(RevisionConflict) as conflict:
        definitions.register(rollback, not_after=LATER)
    assert ":7" in str(conflict.value)
    with pytest.raises(RevisionConflict):
        definitions.register(prior, not_after=LATER)
    with pytest.raises(RevisionConflict):
        definitions.register({**prior, "release_id": FAILED_ID}, not_after=PRIOR_UNTIL)
    assert definitions.specs == before
    # The same registration again changes nothing and is not a conflict.
    definitions.register(prior, not_after=PRIOR_UNTIL)
    assert definitions.specs == before


@pytest.mark.parametrize("problem", ["unregistered", "another_release", "another_job"])
def test_a_rollback_run_may_name_only_its_prior_releases_retained_revisions(problem):
    definitions, prior, failed = catalog()
    rollback = rollback_document(prior, failed, release_id=ROLLBACK_ID)
    proof = next(job for job in rollback["jobs"] if job["id"] == "runtime-proof")
    if problem == "unregistered":
        proof["task"]["task_definition"] = revision_of("runtime-proof", 9)
    elif problem == "another_release":
        # The failed upgrade's own proof revision: registered, but not the prior pair's.
        proof["task"]["task_definition"] = revision_of("runtime-proof", 8)
    else:
        proof["task"]["task_definition"] = revision_of("runtime-grant", 7)
    with pytest.raises(RevisionConflict):
        definitions.require_retained(rollback)


def test_a_later_release_from_the_same_images_gets_new_revisions_and_its_own_deadline():
    # After the retained revisions expire, a rollback needs a new release planned
    # from the prior pair's images: new revisions, never the old ones redated.
    definitions, prior, _failed = catalog()
    before = copy.deepcopy(definitions.specs)
    again = revised(prior, 9)
    again["release_id"] = "55555555-5555-4555-8555-555555555555"
    again["jobs"] = [job for job in again["jobs"] if job["phase"] != "bootstrap"]
    definitions.register(again, not_after=LATER)
    assert definitions.specs[revision_of("runtime-proof", 9)][1]["not_after"] == LATER
    assert {arn: spec for arn, spec in definitions.specs.items() if arn in before} == before
