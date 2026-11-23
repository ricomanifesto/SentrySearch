import assert from 'node:assert/strict';
import test from 'node:test';

import type { ExportConfig } from '../src/lib/api-contracts';
import { buildReportExport } from '../src/lib/report-export';
import { SAMPLE_REPORT } from '../src/lib/sample-report';

const config: ExportConfig = {
  format: 'csv',
  include_content: false,
  include_metadata: false,
  include_tags: false,
  include_sources: false,
};

for (const name of ['=Example', '+Example', '-Example', '@Example', '  =Example', '\tExample', '\rExample', '\nExample']) {
  test(`CSV exports treat ${JSON.stringify(name)} as literal cell text`, () => {
    const csv = buildReportExport([{ ...SAMPLE_REPORT, tool_name: name }], config);
    assert.equal(csv, `"id","tool_name"\n"${SAMPLE_REPORT.id}","'${name}"`);
  });
}

test('CSV literal protection preserves ordinary text and CSV escaping', () => {
  const csv = buildReportExport([{ ...SAMPLE_REPORT, tool_name: 'Example, "Edition"' }], config);
  assert.equal(csv, `"id","tool_name"\n"${SAMPLE_REPORT.id}","Example, ""Edition"""`);
  assert.equal(buildReportExport([], config), 'id,tool_name\n');
});

test('JSON exports preserve report text verbatim', () => {
  const result = JSON.parse(buildReportExport([{ ...SAMPLE_REPORT, tool_name: '+Example' }], { ...config, format: 'json' }));
  assert.equal(result.reports[0].tool_name, '+Example');
});
