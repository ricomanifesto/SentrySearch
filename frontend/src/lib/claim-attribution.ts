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
    if (!exactClaim || claim.source_ids.length === 0 || !attributed.includes(exactClaim)) continue;
    const citations = citationMarkdown(claim.source_ids);
    const inlineCodeClaim = `\`${exactClaim}\``;
    if (attributed.includes(inlineCodeClaim)) {
      attributed = attributed.replace(inlineCodeClaim, `${inlineCodeClaim} ${citations}`);
      continue;
    }
    attributed = attributed.replace(exactClaim, `${exactClaim} ${citations}`);
  }
  return attributed;
}
