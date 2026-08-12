import type { ExportConfig, ReportDetail } from './api-contracts';

type ExportRecord = Record<string, unknown>;

function projectReport(report: ReportDetail, config: ExportConfig): ExportRecord {
  return {
    id: report.id,
    tool_name: report.tool_name,
    ...(config.include_metadata
      ? {
          category: report.category,
          threat_type: report.threat_type,
          quality_score: report.quality_score,
          created_at: report.created_at,
          processing_time_ms: report.processing_time_ms,
          status: report.status,
        }
      : {}),
    ...(config.include_tags ? { search_tags: report.search_tags } : {}),
    ...(config.include_content ? { markdown_content: report.markdown_content ?? null } : {}),
  };
}

function csvCell(value: unknown): string {
  const serialized = Array.isArray(value)
    ? value.join('; ')
    : value === null || value === undefined
      ? ''
      : String(value);
  return `"${serialized.replaceAll('"', '""')}"`;
}

function asCsv(records: ExportRecord[]): string {
  if (records.length === 0) {
    return 'id,tool_name\n';
  }
  const columns = Object.keys(records[0]);
  return [
    columns.map(csvCell).join(','),
    ...records.map((record) => columns.map((column) => csvCell(record[column])).join(',')),
  ].join('\n');
}

function asMarkdown(records: ExportRecord[], generatedAt: string): string {
  const sections = records.map((record) => {
    const metadata = Object.entries(record)
      .filter(([key]) => !['tool_name', 'markdown_content'].includes(key))
      .map(([key, value]) => `- **${key.replaceAll('_', ' ')}:** ${Array.isArray(value) ? value.join(', ') : value ?? ''}`)
      .join('\n');
    const content = typeof record.markdown_content === 'string' ? `\n\n${record.markdown_content}` : '';
    return `## ${record.tool_name}\n\n${metadata}${content}`;
  });
  return [`# SentrySearch report export`, `Generated: ${generatedAt}`, ...sections].join('\n\n');
}

function xmlText(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function asXml(records: ExportRecord[], generatedAt: string): string {
  const reports = records.map((record) => {
    const fields = Object.entries(record)
      .map(([key, value]) => {
        const text = Array.isArray(value) ? value.join('; ') : value;
        return `    <${key}>${xmlText(text)}</${key}>`;
      })
      .join('\n');
    return `  <report>\n${fields}\n  </report>`;
  });
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<sentrysearch-export generated-at="${xmlText(generatedAt)}">`,
    ...reports,
    '</sentrysearch-export>',
  ].join('\n');
}

export function buildReportExport(reports: ReportDetail[], config: ExportConfig): string {
  const generatedAt = new Date().toISOString();
  const records = reports.map((report) => projectReport(report, config));

  switch (config.format) {
    case 'csv':
      return asCsv(records);
    case 'markdown':
      return asMarkdown(records, generatedAt);
    case 'xml':
      return asXml(records, generatedAt);
    case 'json':
      return JSON.stringify(
        {
          export_metadata: { generated_at: generatedAt, total_reports: records.length },
          reports: records,
        },
        null,
        2,
      );
  }
}
