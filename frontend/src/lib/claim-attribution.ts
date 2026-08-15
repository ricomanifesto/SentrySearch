import type { ClaimAttributionEntry } from './api-contracts';

function citationMarkdown(sourceIds: string[]): string {
  return sourceIds.map((sourceId) => `[${sourceId}](#source-${sourceId})`).join(' ');
}

export function applyClaimAttributions(
  markdown: string,
  claims: ClaimAttributionEntry[] | undefined,
): string {
  let attributed = markdown;
  for (const claim of claims ?? []) {
    const exactClaim = claim.claim.trim();
    if (!exactClaim || !attributed.includes(exactClaim)) continue;
    const citations = claim.evidence_role === 'general_practice'
      ? '**General practice**'
      : citationMarkdown(claim.source_ids);
    if (!citations) continue;
    const inlineCodeClaim = `\`${exactClaim}\``;
    if (attributed.includes(inlineCodeClaim)) {
      attributed = attributed.replace(inlineCodeClaim, `${inlineCodeClaim} ${citations}`);
      continue;
    }
    attributed = attributed.replace(exactClaim, `${exactClaim} ${citations}`);
  }
  return attributed;
}
