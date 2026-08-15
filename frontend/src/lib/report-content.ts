export interface ReportContentParts {
  narrative: string;
  appendices: string;
}

export type ReportSectionLink = { id: string; label: string };

function stripPromotedSection(markdown: string, heading: string): string {
  const escapedHeading = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return markdown.replace(
    new RegExp(`^### ${escapedHeading}\\s*$[\\s\\S]*?(?=^#{2,3} \\S|(?![\\s\\S]))`, 'gm'),
    '',
  );
}

function removeDuplicatedEvidenceLists(markdown: string): string {
  return ['Primary Sources', 'Sources', 'Community Resources'].reduce(
    (content, heading) => stripPromotedSection(content, heading),
    markdown,
  );
}

export function reportHeadingId(label: string): string {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '') || 'section';
  return `report-section-${slug}`;
}

export function getReportSectionLinks(markdown: string): ReportSectionLink[] {
  const seen = new Set<string>();
  return [...markdown.matchAll(/^## (.+)$/gm)].flatMap((match) => {
    const label = match[1].trim();
    const id = reportHeadingId(label);
    if (seen.has(id)) return [];
    seen.add(id);
    return [{ id, label }];
  });
}

export function splitReportContent(markdown: string): ReportContentParts {
  const headings = [
    '\n## Quality Assessment Report',
    '\n## Comprehensive Web Search Sources Analysis',
  ];
  const starts = headings
    .map((heading) => markdown.indexOf(heading))
    .filter((position) => position >= 0);
  if (starts.length === 0) {
    return { narrative: removeDuplicatedEvidenceLists(markdown).trim(), appendices: '' };
  }
  const appendixStart = Math.min(...starts);
  return {
    narrative: removeDuplicatedEvidenceLists(markdown.slice(0, appendixStart)).trim(),
    appendices: stripPromotedSection(
      markdown.slice(appendixStart),
      'Cross-Section Consistency',
    ).trim(),
  };
}
