import type {
  AnalystDisposition,
  EvidenceAdmissibility,
  EvidenceAdmissibilityStatus,
} from './api-contracts';

export type ReviewAttentionSummary = {
  headline: string;
  evidenceFindings: string[];
  conflicts: string[];
  recommendations: string[];
  unverifiedRecommendations: string[];
};

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];
}

function unverifiedRecommendationList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== 'object') return [];
    const record = item as Record<string, unknown>;
    const recommendation = typeof record.recommendation === 'string' ? record.recommendation.trim() : '';
    const reason = typeof record.reason === 'string' ? record.reason.trim() : '';
    return recommendation ? [`${recommendation}${reason ? ` — ${reason}` : ''}`] : [];
  });
}

function sentenceList(values: string[]): string {
  if (values.length < 2) return values[0] ?? '';
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(', ')}, and ${values.at(-1)}`;
}

export function getRecordedConflictCount(
  assessment: Record<string, unknown> | null | undefined,
): number {
  if (!assessment?.consistency || typeof assessment.consistency !== 'object') return 0;
  const consistency = assessment.consistency as Record<string, unknown>;
  return stringList(consistency.inconsistencies).length;
}

export function getReviewAttentionSummary(
  assessment: Record<string, unknown> | null | undefined,
  sourceCount: number,
  analystDisposition: AnalystDisposition = 'unreviewed',
  evidenceStatus: EvidenceAdmissibilityStatus = 'passed',
  evidenceAdmissibility?: EvidenceAdmissibility | null,
  acceptanceEligible = false,
): ReviewAttentionSummary | null {
  const evidenceFindings = evidenceAdmissibility?.blocking_findings ?? [];
  if (!assessment) {
    if (evidenceStatus !== 'passed') {
      return {
        headline: evidenceStatus === 'blocked'
          ? 'Operational reuse is blocked by deterministic evidence checks.'
          : 'Operational reuse is blocked because evidence admissibility was not assessed.',
        evidenceFindings,
        conflicts: [],
        recommendations: [],
        unverifiedRecommendations: [],
      };
    }
    return sourceCount > 0
      ? null
      : { headline: 'No structured source evidence is attached.', evidenceFindings: [], conflicts: [], recommendations: [], unverifiedRecommendations: [] };
  }
  const summary = assessment.summary && typeof assessment.summary === 'object'
    ? assessment.summary as Record<string, unknown>
    : {};
  const consistency = assessment.consistency && typeof assessment.consistency === 'object'
    ? assessment.consistency as Record<string, unknown>
    : {};
  const conflicts = stringList(consistency.inconsistencies);
  const recommendations = [
    ...stringList(assessment.recommendations),
    ...stringList(consistency.recommendations),
  ].filter((value, index, values) => values.indexOf(value) === index).slice(0, 5);
  const unverifiedRecommendations = unverifiedRecommendationList(
    assessment.unverified_recommendations,
  );
  const failed = Number(summary.failed_sections ?? 0);
  const unavailable = Number(summary.unavailable_sections ?? 0);
  const enhance = Number(summary.enhance_sections ?? 0);
  const reasons = [
    conflicts.length ? `${conflicts.length} cross-section conflict${conflicts.length === 1 ? '' : 's'}` : '',
    failed ? `${failed} failed section${failed === 1 ? '' : 's'}` : '',
    unavailable ? `${unavailable} unavailable section${unavailable === 1 ? '' : 's'}` : '',
    enhance ? `${enhance} section${enhance === 1 ? '' : 's'} marked to enhance` : '',
    sourceCount < 1 ? 'no operational source evidence' : '',
    evidenceStatus === 'blocked' ? `${evidenceFindings.length || 1} deterministic evidence blocker${evidenceFindings.length === 1 ? '' : 's'}` : '',
    evidenceStatus === 'unassessed' ? 'no deterministic evidence-admissibility record' : '',
    unverifiedRecommendations.length
      ? `${unverifiedRecommendations.length} unsupported evaluator suggestion${unverifiedRecommendations.length === 1 ? '' : 's'}`
      : '',
  ].filter(Boolean);
  return reasons.length > 0
    ? {
        headline: conflicts.length > 0
          ? analystDisposition === 'accepted' && acceptanceEligible
            ? `An analyst accepted this evaluation vintage with ${sentenceList(reasons)} still recorded below.`
            : analystDisposition === 'accepted'
              ? `An earlier analyst acceptance remains in history, but operational reuse is blocked by ${sentenceList(reasons)}.`
            : analystDisposition === 'rejected'
              ? `This evaluation vintage was rejected; ${sentenceList(reasons)} remain in its audit record.`
              : analystDisposition === 'needs_revision'
                ? `Operational reuse remains blocked by ${sentenceList(reasons)}.`
                : `Operational reuse is blocked by ${sentenceList(reasons)} until an analyst records a disposition.`
          : `Analyst review is required: ${sentenceList(reasons)}.`,
        evidenceFindings,
        conflicts,
        recommendations,
        unverifiedRecommendations,
      }
    : null;
}
