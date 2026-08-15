"""Bounded concurrent evaluation for threat profile sections."""

from __future__ import annotations

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Optional

from src.core.section_validator import SectionValidator
from src.core.source_ledger import CLAIM_CLASS_SECTIONS
from src.core.threat_profile_schema import EVIDENCE_ENHANCEMENT_MODELS
from src.core.validation_criteria import SECTION_CRITERIA, select_profile_sections

ProgressCallback = Callable[[float, str], None]
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SectionEnhancement:
    """One proposed content change and its evaluation result."""

    content: dict
    validation: dict


class ParallelSectionValidator(SectionValidator):
    """Evaluate independent sections with separate validation and enhancement limits."""

    def __init__(
        self,
        client,
        max_concurrent_validations: int = 3,
        max_concurrent_enhancements: int = 2,
    ) -> None:
        super().__init__(client)
        if max_concurrent_validations < 1 or max_concurrent_enhancements < 1:
            raise ValueError("Concurrency limits must be positive")

        self.max_concurrent_validations = max_concurrent_validations
        self.max_concurrent_enhancements = max_concurrent_enhancements

    def validate_complete_profile(
        self,
        profile: dict,
        progress_callback: Optional[ProgressCallback] = None,
        tool_name: str | None = None,
        evidence_text: str | None = None,
    ) -> dict:
        """Use bounded concurrency through the validator's existing public surface."""

        return self.validate_complete_profile_parallel(
            profile, progress_callback, tool_name, evidence_text
        )

    def validate_complete_profile_parallel(
        self,
        profile: dict,
        progress_callback: Optional[ProgressCallback] = None,
        tool_name: str | None = None,
        evidence_text: str | None = None,
    ) -> dict:
        """Evaluate eligible sections concurrently and aggregate their final state."""

        started_at = time.perf_counter()
        sections_to_validate, skipped_sections = select_profile_sections(profile)
        self.profile_source_context = dict(profile.get("webSearchSources") or {})
        self.profile_claim_attribution = dict(profile.get("claimAttribution") or {})
        self.profile_evidence_text = evidence_text or ""
        results: dict[str, Any] = {
            "section_validations": {},
            "overall_score": None,
            "needs_improvement": False,
            "critical_issues": [],
            "summary": {},
            "recommendations": [],
            "validation_attempts": {},
            "skipped_sections": skipped_sections,
            "parallel_metrics": {},
        }

        if progress_callback:
            progress_callback(0.8, "Validating profile sections...")

        validation_started_at = time.perf_counter()
        results["section_validations"] = self._validate_sections_parallel(
            sections_to_validate, progress_callback
        )
        validation_duration = time.perf_counter() - validation_started_at
        results["validation_attempts"] = {
            section_name: 1 for section_name in results["section_validations"]
        }

        enhancements: dict[str, SectionEnhancement] = {}
        enhancement_duration = 0.0
        if tool_name:
            enhancement_started_at = time.perf_counter()
            enhancements = self._enhance_sections_parallel(
                results,
                profile,
                tool_name,
                progress_callback,
                evidence_text=evidence_text,
            )
            enhancement_duration = time.perf_counter() - enhancement_started_at

            # Workers only propose changes. Apply them on the caller thread in
            # profile order so readers never observe a partially updated profile.
            for section_name in sections_to_validate:
                enhancement = enhancements.get(section_name)
                if enhancement is None:
                    continue
                profile[section_name] = enhancement.content
                results["section_validations"][section_name] = enhancement.validation
                results["validation_attempts"][section_name] = 2

        if progress_callback:
            progress_callback(0.95, "Checking cross-section consistency...")
        results["consistency"] = self._check_consistency(profile)
        results["critical_issues"] = self._find_critical_issues(results["section_validations"])
        results["overall_score"] = self._calculate_overall_score(results)
        results["needs_improvement"] = bool(results["critical_issues"]) or (
            results["overall_score"] is None or results["overall_score"] < 3.5
        )
        results["summary"] = self._generate_summary(results)
        results["recommendations"] = self._generate_recommendations(results)

        total_duration = time.perf_counter() - started_at
        results["parallel_metrics"] = {
            "total_duration_seconds": round(total_duration, 3),
            "validation_duration_seconds": round(validation_duration, 3),
            "enhancement_duration_seconds": round(enhancement_duration, 3),
            "sections_processed": len(sections_to_validate),
            "sections_enhanced": len(enhancements),
            "max_concurrent_validations": self.max_concurrent_validations,
            "max_concurrent_enhancements": self.max_concurrent_enhancements,
        }

        if progress_callback:
            progress_callback(1.0, "Profile validation complete.")

        return results

    def _validate_sections_parallel(
        self,
        sections: dict,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> dict:
        """Evaluate sections with a bounded worker pool and deterministic output order."""

        if not sections:
            return {}

        def validate_section(section_name: str, section_content: dict) -> tuple[str, dict]:
            try:
                result = self.validate_section(section_name, deepcopy(section_content))
            except Exception as error:
                logger.warning("Section validation failed for %s: %s", section_name, error)
                criteria = SECTION_CRITERIA[section_name]
                result = self._create_error_validation(section_name, criteria.is_critical)
            return section_name, result

        completed_results: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=self.max_concurrent_validations) as executor:
            futures = {
                executor.submit(validate_section, section_name, section_content): section_name
                for section_name, section_content in sections.items()
            }
            for completed_count, future in enumerate(as_completed(futures), start=1):
                section_name, validation = future.result()
                completed_results[section_name] = validation
                if progress_callback:
                    progress = 0.8 + (0.1 * completed_count / len(sections))
                    progress_callback(
                        progress,
                        f"Validated {section_name} ({completed_count}/{len(sections)})",
                    )

        return {section_name: completed_results[section_name] for section_name in sections}

    def _enhance_sections_parallel(
        self,
        validation_results: dict,
        profile: dict,
        tool_name: str,
        progress_callback: Optional[ProgressCallback] = None,
        evidence_text: str | None = None,
    ) -> dict[str, SectionEnhancement]:
        """Propose and evaluate section enhancements without mutating shared state."""

        candidates: list[tuple[float, int, str]] = []
        attribution = profile.get("claimAttribution")
        claim_bound_sections = (
            frozenset(CLAIM_CLASS_SECTIONS.values())
            if isinstance(attribution, dict) and attribution.get("schemaVersion") == "2"
            else frozenset()
        )
        for index, (section_name, validation) in enumerate(
            validation_results["section_validations"].items()
        ):
            score = validation.get("scores", {}).get("overall")
            if (
                isinstance(score, (int, float))
                and 0 <= score < SECTION_CRITERIA[section_name].minimum_score
                and (not evidence_text or section_name in EVIDENCE_ENHANCEMENT_MODELS)
                and section_name not in claim_bound_sections
            ):
                candidates.append((float(score), index, section_name))
        sections_to_enhance = [section_name for _, _, section_name in sorted(candidates)[:5]]
        if not sections_to_enhance:
            return {}

        if progress_callback:
            progress_callback(
                0.9,
                f"Enhancing {len(sections_to_enhance)} low-scoring sections...",
            )

        profile_snapshot = deepcopy(profile)

        def enhance_section(section_name: str) -> tuple[str, SectionEnhancement | None]:
            try:
                original_content = profile_snapshot[section_name]
                if evidence_text:
                    enhanced_content = self._enhance_section_from_attested_evidence(
                        section_name,
                        deepcopy(original_content),
                        tool_name,
                        evidence_text,
                    )
                else:
                    enhanced_content = self._enhance_section_with_web_search(
                        section_name, deepcopy(original_content), tool_name
                    )
                if not enhanced_content or enhanced_content == original_content:
                    return section_name, None

                validation = self.validate_section(section_name, enhanced_content)
                previous_score = (
                    validation_results["section_validations"][section_name]
                    .get("scores", {})
                    .get("overall")
                )
                enhanced_score = validation.get("scores", {}).get("overall")
                if (
                    not isinstance(previous_score, (int, float))
                    or not isinstance(enhanced_score, (int, float))
                    or enhanced_score <= previous_score
                ):
                    return section_name, None
                validation["enhanced"] = True
                return section_name, SectionEnhancement(
                    content=enhanced_content,
                    validation=validation,
                )
            except Exception as error:
                logger.warning("Section enhancement failed for %s: %s", section_name, error)
                return section_name, None

        completed_enhancements: dict[str, SectionEnhancement] = {}
        with ThreadPoolExecutor(max_workers=self.max_concurrent_enhancements) as executor:
            futures = {
                executor.submit(enhance_section, section_name): section_name
                for section_name in sections_to_enhance
            }
            for completed_count, future in enumerate(as_completed(futures), start=1):
                section_name, enhancement = future.result()
                if enhancement is not None:
                    completed_enhancements[section_name] = enhancement
                if progress_callback:
                    progress = 0.9 + (0.05 * completed_count / len(sections_to_enhance))
                    progress_callback(
                        progress,
                        f"Enhanced {section_name} ({completed_count}/{len(sections_to_enhance)})",
                    )

        return {
            section_name: completed_enhancements[section_name]
            for section_name in sections_to_enhance
            if section_name in completed_enhancements
        }
