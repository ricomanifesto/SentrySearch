"""The synthesis prompt's JSON skeleton stays aligned with the Pydantic profile."""

import json
from typing import Any, get_args, get_origin

from pydantic import BaseModel

from src.core.threat_profile_generator import synthesis_prompt
from src.core.threat_profile_schema import ThreatProfile

# Generation-only fields the application derives; the model must not emit them.
_APPLICATION_OWNED = {"claimAttribution"}


def _skeleton() -> dict[str, Any]:
    prompt = synthesis_prompt(
        "Example Threat",
        research_text="dossier",
        source_catalog="[]",
        withheld_source_count=0,
    )
    start = prompt.index("following JSON format:\n\n") + len("following JSON format:\n\n")
    end = prompt.index("\n\nCRITICAL INSTRUCTIONS FOR OUTPUT:")
    return json.loads(prompt[start:end])


def _model_of(annotation: Any) -> type[BaseModel] | None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for argument in get_args(annotation):
        model = _model_of(argument)
        if model is not None and get_origin(annotation) is list:
            return model
    return None


def _mismatches(model: type[BaseModel], skeleton: Any, path: str) -> list[str]:
    if not isinstance(skeleton, dict):
        return [f"{path} is not an object in the skeleton"]
    problems: list[str] = []
    fields = {(field.alias or name): field for name, field in model.model_fields.items()}
    for key in skeleton:
        if key not in fields:
            problems.append(f"{path}.{key} is not in the schema")
    for alias, field in fields.items():
        if alias in _APPLICATION_OWNED:
            continue
        if alias not in skeleton:
            if field.is_required():
                problems.append(f"{path}.{alias} is required but missing from the skeleton")
            continue
        value = skeleton[alias]
        annotation = field.annotation
        nested = _model_of(annotation)
        if nested is None:
            continue
        if get_origin(annotation) is list:
            if not isinstance(value, list):
                problems.append(f"{path}.{alias} must be an array in the skeleton")
            elif value and isinstance(value[0], dict):
                problems.extend(_mismatches(nested, value[0], f"{path}.{alias}[0]"))
        else:
            problems.extend(_mismatches(nested, value, f"{path}.{alias}"))
    return problems


def test_prompt_skeleton_keys_match_the_threat_profile_schema():
    assert _mismatches(ThreatProfile, _skeleton(), "profile") == []
