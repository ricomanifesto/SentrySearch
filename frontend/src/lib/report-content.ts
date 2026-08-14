export interface ReportContentParts {
  narrative: string;
  appendices: string;
}

export function splitReportContent(markdown: string): ReportContentParts {
  const headings = [
    '\n## Quality Assessment Report',
    '\n## Comprehensive Web Search Sources Analysis',
  ];
  const starts = headings
    .map((heading) => markdown.indexOf(heading))
    .filter((position) => position >= 0);
  if (starts.length === 0) return { narrative: markdown, appendices: '' };
  const appendixStart = Math.min(...starts);
  return {
    narrative: markdown.slice(0, appendixStart).trim(),
    appendices: markdown.slice(appendixStart).trim(),
  };
}
