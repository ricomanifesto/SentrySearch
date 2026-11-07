import type { ClaimAttributionEntry } from './api-contracts';

function citationMarkdown(sourceIds: string[]): string {
  return sourceIds.map((sourceId) => `[${sourceId}](#source-${sourceId})`).join(' ');
}

type CodeRange = { start: number; end: number; kind: 'fenced' | 'inline' };

function markdownCodeRanges(markdown: string): CodeRange[] {
  const ranges: CodeRange[] = [];
  const fencePattern = /^ {0,3}(`{3,}|~{3,})[^\n]*(?:\n|$)/gm;
  let opener = fencePattern.exec(markdown);
  while (opener) {
    const delimiter = opener[1];
    const closePattern = new RegExp(`^ {0,3}${delimiter[0]}{${delimiter.length},}\\s*$`, 'gm');
    closePattern.lastIndex = fencePattern.lastIndex;
    const closer = closePattern.exec(markdown);
    const end = closer ? closer.index + closer[0].length : markdown.length;
    ranges.push({ start: opener.index, end, kind: 'fenced' });
    fencePattern.lastIndex = end;
    opener = fencePattern.exec(markdown);
  }

  const ticks = /`+/g;
  let inlineOpener = ticks.exec(markdown);
  while (inlineOpener) {
    const insideFence = ranges.some(
      (range) => range.kind === 'fenced'
        && inlineOpener!.index >= range.start
        && inlineOpener!.index < range.end,
    );
    if (insideFence) {
      const fence = ranges.find(
        (range) => range.kind === 'fenced'
          && inlineOpener!.index >= range.start
          && inlineOpener!.index < range.end,
      );
      ticks.lastIndex = fence?.end ?? ticks.lastIndex;
      inlineOpener = ticks.exec(markdown);
      continue;
    }
    const delimiter = inlineOpener[0];
    const close = markdown.indexOf(delimiter, ticks.lastIndex);
    if (close < 0 || markdown.slice(ticks.lastIndex, close).includes('\n')) {
      inlineOpener = ticks.exec(markdown);
      continue;
    }
    ranges.push({
      start: inlineOpener.index,
      end: close + delimiter.length,
      kind: 'inline',
    });
    ticks.lastIndex = close + delimiter.length;
    inlineOpener = ticks.exec(markdown);
  }
  return ranges.sort((left, right) => left.start - right.start);
}

export function applyClaimAttributions(
  markdown: string,
  claims: ClaimAttributionEntry[] | undefined,
): string {
  type Edit = { start: number; end: number; replacement: string };
  const edits: Edit[] = [];
  const codeRanges = markdownCodeRanges(markdown);
  const overlaps = (start: number, end: number) => edits.some(
    (edit) => start < edit.end && end > edit.start,
  );
  const orderedClaims = [...(claims ?? [])].sort(
    (left, right) => right.claim.trim().length - left.claim.trim().length,
  );
  for (const claim of orderedClaims) {
    const exactClaim = claim.claim.trim();
    if (!exactClaim) continue;
    const citations = claim.evidence_role === 'general_practice'
      ? '**General practice**'
      : citationMarkdown(claim.source_ids);
    if (!citations) continue;

    let searchFrom = 0;
    while (searchFrom < markdown.length) {
      const claimStart = markdown.indexOf(exactClaim, searchFrom);
      if (claimStart < 0) break;
      const claimEnd = claimStart + exactClaim.length;
      const codeRange = codeRanges.find(
        (range) => claimStart >= range.start && claimEnd <= range.end,
      );
      if (codeRange?.kind === 'fenced') {
        searchFrom = codeRange.end;
        continue;
      }
      const inlineValue = codeRange?.kind === 'inline'
        ? markdown
          .slice(codeRange.start, codeRange.end)
          .replace(/^`+|`+$/g, '')
          .trim()
        : null;
      if (codeRange?.kind === 'inline' && inlineValue !== exactClaim) {
        searchFrom = codeRange.end;
        continue;
      }
      const start = codeRange?.kind === 'inline' ? codeRange.start : claimStart;
      const end = codeRange?.kind === 'inline' ? codeRange.end : claimEnd;
      if (!overlaps(start, end)) {
        const original = markdown.slice(start, end);
        edits.push({ start, end, replacement: `${original} ${citations}` });
        break;
      }
      searchFrom = claimEnd;
    }
  }

  return edits
    .sort((left, right) => right.start - left.start)
    .reduce(
      (attributed, edit) => (
        `${attributed.slice(0, edit.start)}${edit.replacement}${attributed.slice(edit.end)}`
      ),
      markdown,
    );
}
