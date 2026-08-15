export type ReviewAttentionSummary = {
  headline: string;
  conflicts: string[];
  recommendations: string[];
};

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];
}

function sentenceList(values: string[]): string {
  if (values.length < 2) return values[0] ?? '';
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(', ')}, and ${values.at(-1)}`;
}

export function getReviewAttentionSummary(
  assessment: Record<string, unknown> | null | undefined,
  sourceCount: number,
): ReviewAttentionSummary | null {
  if (!assessment) {
    return sourceCount > 0
      ? null
      : { headline: 'No structured source evidence is attached.', conflicts: [], recommendations: [] };
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
  const failed = Number(summary.failed_sections ?? 0);
  const unavailable = Number(summary.unavailable_sections ?? 0);
  const enhance = Number(summary.enhance_sections ?? 0);
  const reasons = [
    conflicts.length ? `${conflicts.length} cross-section conflict${conflicts.length === 1 ? '' : 's'}` : '',
    failed ? `${failed} failed section${failed === 1 ? '' : 's'}` : '',
    unavailable ? `${unavailable} unavailable section${unavailable === 1 ? '' : 's'}` : '',
    enhance ? `${enhance} section${enhance === 1 ? '' : 's'} marked to enhance` : '',
    sourceCount < 1 ? 'no structured source evidence' : '',
  ].filter(Boolean);
  return reasons.length > 0
    ? {
        headline: `${sentenceList(reasons)} ${reasons.length === 1 ? 'requires' : 'require'} review.`,
        conflicts,
        recommendations,
      }
    : null;
}
