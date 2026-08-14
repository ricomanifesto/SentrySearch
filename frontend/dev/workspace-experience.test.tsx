import assert from 'node:assert/strict';
import test from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';

import { DashboardBriefingSignals } from '../src/components/DashboardBriefingSignals';
import { ReviewStatusBanner } from '../src/components/report/ReviewStatusBanner';
import type { AnalyticsDashboard, ExportConfig } from '../src/lib/api-contracts';
import { splitReportContent } from '../src/lib/report-content';
import { buildReportExport } from '../src/lib/report-export';
import {
  reportQueryFromSearchParams,
  reportQuerySearchParams,
} from '../src/lib/report-query';
import { SAMPLE_REPORT } from '../src/lib/sample-report';

const emptyDashboard: AnalyticsDashboard = {
  summary: {
    total_reports: 0,
    reports_this_week: 0,
    avg_quality_score: null,
    scored_reports: 0,
    needs_attention_reports: 0,
  },
  threat_distribution: {},
  quality_distribution: [],
  recent_activity: [],
};

test('slow analytics renders a named loading state without impersonating an empty account', () => {
  const html = renderToStaticMarkup(
    <DashboardBriefingSignals isLoading={true} />,
  );

  assert.match(html, /role="status"/);
  assert.match(html, /aria-label="Loading workspace briefing"/);
  assert.doesNotMatch(html, />0</);
  assert.doesNotMatch(html, /No scored reports yet/);
});

test('a genuinely empty workspace states zero reports and no scored reports honestly', () => {
  const html = renderToStaticMarkup(
    <DashboardBriefingSignals analytics={emptyDashboard} isLoading={false} />,
  );

  assert.match(html, /Intelligence library/);
  assert.match(html, /No scored reports yet/);
  assert.doesNotMatch(html, /Loading workspace briefing/);
});

test('an unscored saved report offers evaluator-only recovery without hiding its narrative', () => {
  const html = renderToStaticMarkup(
    <ReviewStatusBanner status="needs_evaluation" />,
  );

  assert.match(html, /Needs evaluation/);
  assert.match(html, /narrative is preserved/);
  assert.match(html, />Retry evaluation</);
});

test('evaluation progress is announced politely to assistive technology', () => {
  const html = renderToStaticMarkup(
    <ReviewStatusBanner status="evaluation_pending" />,
  );

  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /Evaluation in progress/);
});

test('report-library filters survive a URL round trip', () => {
  const initial = reportQueryFromSearchParams(new URLSearchParams(
    'query=socgholish&threat_type=loader&min_quality=3.5&date_range=90&sort_by=quality_score&sort_order=asc',
  ));
  const restored = reportQueryFromSearchParams(reportQuerySearchParams(initial, 3));

  assert.deepEqual(restored, initial);
  assert.equal(reportQuerySearchParams(initial, 3).get('page'), '3');
});

test('evaluation detail is separated from the operational narrative', () => {
  const parts = splitReportContent([
    '# Example',
    '',
    '## Findings',
    '',
    'Operational evidence.',
    '',
    '## Quality Assessment Report',
    '',
    'Evaluator notes.',
  ].join('\n'));

  assert.match(parts.narrative, /Operational evidence/);
  assert.doesNotMatch(parts.narrative, /Evaluator notes/);
  assert.match(parts.appendices, /Quality Assessment Report/);
});

test('downloaded exports carry the canonical evidence ledger and route attestation', () => {
  const config: ExportConfig = {
    format: 'json',
    include_content: true,
    include_metadata: true,
    include_tags: false,
    include_sources: true,
  };
  const exported = JSON.parse(buildReportExport([SAMPLE_REPORT], config));
  const record = exported.reports[0];

  assert.equal(record.web_sources.length, SAMPLE_REPORT.web_sources.length);
  assert.equal(record.web_sources[0].url, SAMPLE_REPORT.web_sources[0].url);
  assert.equal(record.review_status, 'reviewable');
  assert.ok(Object.hasOwn(record, 'generation_route'));
  assert.ok(Object.hasOwn(record, 'evaluation_route'));
  assert.match(record.markdown_content, /Executive Summary/);
});
