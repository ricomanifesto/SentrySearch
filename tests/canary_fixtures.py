"""Test-only HTTP boundaries for the real generation/evaluation worker.

Never ship this module or its synthetic profile in a service image. The CISA URL
is an exact-address fixture key, not a claim that the synthetic page was fetched
from CISA. MockTransport performs no network I/O. The ordinary source parser,
public-address checks, classification, evidence gates and score math remain live.
No pytest import is needed when this module is mounted into a worker container.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import ExitStack
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import socket
from threading import Lock
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx

from src.core import report_evaluator, source_snapshot, threat_profile_generator
from src.core.openrouter_client import ModelClient

SOURCE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-031a"
SOURCE_TEXT = (
    "Example Threat malware analysis and mitigation. Remote access. example.exe. "
    "HTTPS callbacks. Process creation. Unexpected service creation. Application control. "
    "Monitor service creation. Isolate affected host. Rebuild compromised systems."
)
SOURCE_SHA256 = "6208dd694a0c7a30e9d97f45d9815be0caa97dcce704860d01904f2c5a09900d"
MODEL_URL = "https://model.canary.invalid/api/v1/chat/completions"
CAPTURE_TIME = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


class WorkerFixtures:
    """Own process-local patches and bounded, thread-safe observation receipts."""

    def __init__(self, *, bad_excerpt: bool = False) -> None:
        self.bad_excerpt = bad_excerpt
        # A synthetic globally routable answer exercises real IP validation; no
        # connection is made to this address, and it is not CISA DNS evidence.
        self.source_address = "93.184.216.34"
        self.request_counts: dict[str, int] = {}
        self.source_requests = 0
        self.snapshots: list[dict[str, Any]] = []
        self._lock = Lock()
        self._patches = ExitStack()
        self._profile = json.loads(
            (Path(__file__).parent / "fixtures" / "canary-profile.json").read_text()
        )

    def __enter__(self) -> WorkerFixtures:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Restore only the exact module-bound objects owned by this install."""
        self._patches.close()

    def _model_profile(self) -> dict[str, Any]:
        profile = deepcopy(self._profile)
        if self.bad_excerpt:

            def corrupt(value: Any) -> None:
                if isinstance(value, dict):
                    for support in value.get("supportingEvidence", []):
                        support["excerpt"] = "This excerpt never appeared in the captured page."
                    for child in value.values():
                        corrupt(child)
                elif isinstance(value, list):
                    for child in value:
                        corrupt(child)

            corrupt(profile)
        return profile

    def _model_response(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or str(request.url) != MODEL_URL:
            raise AssertionError("Unexpected model fixture request")
        if len(request.content) > 256_000:
            raise AssertionError("Model fixture request exceeded its byte bound")
        payload = json.loads(request.content)
        response_format = payload.get("response_format", {})
        schema_name = response_format.get("json_schema", {}).get("name")
        annotations: list[dict[str, Any]] = []
        if payload.get("tools"):
            kind = "research"
            content = SOURCE_TEXT
            annotations = [
                {
                    "type": "url_citation",
                    "url_citation": {
                        "url": SOURCE_URL,
                        "title": "Example Threat malware analysis and mitigation",
                        "content": SOURCE_TEXT,
                    },
                }
            ]
        elif schema_name == "SectionEvaluation":
            kind = "section"
            content = json.dumps(
                {
                    "scores": {
                        key: 4.5
                        for key in (
                            "completeness",
                            "technical_accuracy",
                            "source_quality",
                            "actionability",
                            "relevance",
                        )
                    },
                    "missing_information": [],
                    "weak_areas": [],
                    "technical_issues": [],
                    "specific_improvements": [],
                    "recommendation": "PASS",
                    "reasoning": "Deterministic external evaluator response for local tests.",
                }
            )
        elif schema_name == "ConsistencyEvaluation":
            kind = "consistency"
            content = json.dumps(
                {"consistency_score": 4.5, "inconsistencies": [], "recommendations": []}
            )
        elif response_format.get("type") == "json_object":
            kind = "synthesis"
            profile = self._model_profile()
            messages = json.dumps(payload.get("messages", []))
            if "CORRECTION ATTEMPT AFTER A FAILED EVIDENCE GATE" in messages:
                # Return valid correction syntax with the same defective evidence
                # in the negative case. The real gate must still reject it.
                choices = {
                    "riskFactor": (
                        None,
                        profile["threatIntelligence"]["riskAssessment"]["riskFactors"][0],
                    ),
                    "forensicArtifact": (
                        "fileSystemArtifacts",
                        profile["forensicArtifacts"]["fileSystemArtifacts"][0],
                    ),
                    "detectionIndicator": (
                        "filenames",
                        profile["detectionAndMitigation"]["iocs"]["filenames"][0],
                    ),
                    "mitigationAction": (
                        "detectionMethods",
                        profile["mitigationAndResponse"]["detectionMethods"][0],
                    ),
                }
                profile = {}
                for name, (field, item) in choices.items():
                    item.pop("sourceIds")
                    profile[name] = {**item, **({"claimField": field} if field else {})}
            content = json.dumps(profile)
        else:
            raise AssertionError("Unexpected model fixture schema")
        with self._lock:
            self.request_counts[kind] = self.request_counts.get(kind, 0) + 1
        return httpx.Response(
            200,
            request=request,
            json={
                "id": f"local-fixture-{kind}",
                "object": "chat.completion",
                "model": payload["model"],
                "provider": "LocalFixture",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": content,
                            "annotations": annotations,
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            },
        )

    def create_client(self) -> ModelClient:
        return ModelClient(
            base_url=MODEL_URL.removesuffix("/chat/completions"),
            api_key="fixture-only-not-a-credential",
            timeout=2.0,
            transport=httpx.MockTransport(self._model_response),
        )

    def _resolve(self, host: str, port: int, **kwargs: Any) -> list[tuple]:
        if host != "www.cisa.gov" or port != 443 or kwargs.get("type") != socket.SOCK_STREAM:
            raise OSError("Unexpected source fixture DNS request")
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (self.source_address, port),
            )
        ]

    def _source_response(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET" or str(request.url) != SOURCE_URL:
            raise AssertionError("Unexpected source fixture HTTP request")
        with self._lock:
            self.source_requests += 1
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/html; charset=utf-8"},
            content=(
                f"<html><body>{SOURCE_TEXT}<script>not visible evidence</script></body></html>"
            ).encode(),
        )

    def _fetch(self, source: Mapping[str, Any]) -> Mapping[str, Any]:
        if source.get("url") != SOURCE_URL:
            raise ValueError("Unexpected source fixture URL")
        with httpx.Client(
            transport=httpx.MockTransport(self._source_response),
            follow_redirects=False,
            timeout=2.0,
            trust_env=False,
        ) as client:
            snapshot = source_snapshot.capture_source_snapshot(
                source, client=client, now=CAPTURE_TIME
            )
        with self._lock:
            self.snapshots.append(snapshot)
        return snapshot

    def capture_sources(self, sources: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return source_snapshot.capture_source_snapshots(sources, fetcher=self._fetch)


def install_worker_fixtures(*, bad_excerpt: bool = False) -> WorkerFixtures:
    """Install once at worker-process start; close/context-exit restores boundaries."""
    fixtures = WorkerFixtures(bad_excerpt=bad_excerpt)
    try:
        for module in (threat_profile_generator, report_evaluator):
            fixtures._patches.enter_context(
                patch.object(module, "create_model_client", fixtures.create_client)
            )
        fixtures._patches.enter_context(
            patch.object(
                threat_profile_generator, "capture_source_snapshots", fixtures.capture_sources
            )
        )
        # Replace only this module's DNS boundary, not socket.getaddrinfo used by
        # database clients or other real local services in the worker process.
        fixtures._patches.enter_context(
            patch.object(
                source_snapshot,
                "socket",
                SimpleNamespace(
                    getaddrinfo=fixtures._resolve,
                    SOCK_STREAM=socket.SOCK_STREAM,
                ),
            )
        )
    except BaseException:
        fixtures.close()
        raise
    return fixtures
