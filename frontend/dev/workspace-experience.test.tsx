import assert from 'node:assert/strict';
import test from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';

import { DashboardBriefingSignals } from '../src/components/DashboardBriefingSignals';
import { ReviewStatusBanner } from '../src/components/report/ReviewStatusBanner';
import { AnalystDispositionPanel } from '../src/components/report/AnalystDispositionPanel';
import { NavigationSessionActions } from '../src/components/layout/Navigation';
import type { AnalyticsDashboard, ExportConfig } from '../src/lib/api-contracts';
import { getReportSectionLinks, splitReportContent } from '../src/lib/report-content';
import { getReviewAttentionSummary } from '../src/lib/review-attention';
import { getGenerationFailurePresentation } from '../src/lib/generation-failure';
import { buildReportExport } from '../src/lib/report-export';
import {
  reportQueryFromSearchParams,
  reportQuerySearchParams,
  reviewStatusesForState,
  toSearchFilters,
  defaultReportQuery,
} from '../src/lib/report-query';
import { SAMPLE_REPORT } from '../src/lib/sample-report';

const emptyDashboard: AnalyticsDashboard = {
  summary: {
    total_reports: 0,
    runs_this_week: 0,
    completed_reports_this_week: 0,
    failed_reports_this_week: 0,
    avg_quality_score: null,
    scored_reports: 0,
    needs_attention_reports: 0,
    unresolved_reports: 0,
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

test('session resolution never paints public sign-in controls in an authenticated shell', () => {
  const html = renderToStaticMarkup(
    <NavigationSessionActions loading={true} onSignOut={() => undefined} />,
  );

  assert.match(html, /Resolving workspace session/);
  assert.doesNotMatch(html, /Sign in/);
  assert.doesNotMatch(html, /Sign up/);
});

test('report-library filters survive a URL round trip', () => {
  const initial = reportQueryFromSearchParams(new URLSearchParams(
    'query=socgholish&threat_type=loader&min_quality=3.5&date_range=90&review_state=all&sort_by=quality_score&sort_order=asc',
  ));
  const restored = reportQueryFromSearchParams(reportQuerySearchParams(initial, 3));

  assert.deepEqual(restored, initial);
  assert.equal(reportQuerySearchParams(initial, 3).get('page'), '3');
});

test('the unresolved queue delegates current-vintage judgment semantics to the API', () => {
  assert.equal(reviewStatusesForState('actionable'), undefined);
  assert.equal(toSearchFilters({ ...defaultReportQuery }).requires_action, true);
  assert.deepEqual(toSearchFilters({ ...defaultReportQuery, reviewState: 'accepted' }).analyst_dispositions, ['accepted']);
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

test('promoted conflicts and source ledgers are not duplicated in the report body', () => {
  const parts = splitReportContent([
    '# Example',
    '',
    '## Web Search Sources & Research Methodology',
    '',
    '### Primary Sources',
    '',
    '- https://example.com/evidence',
    '',
    '### Data Quality Assessment',
    '',
    'Freshness was reviewed.',
    '',
    '## Findings',
    '',
    'Operational evidence.',
    '',
    '## Quality Assessment Report',
    '',
    '### Cross-Section Consistency',
    '',
    '- Timeline conflicts with metadata.',
    '',
    '### Section Scores',
    '',
    '| Section | Score |',
  ].join('\n'));

  assert.doesNotMatch(parts.narrative, /example\.com\/evidence/);
  assert.match(parts.narrative, /Freshness was reviewed/);
  assert.doesNotMatch(parts.appendices, /Timeline conflicts/);
  assert.match(parts.appendices, /Section Scores/);
});

test('report outline ids are deterministic and duplicate headings collapse to one link', () => {
  assert.deepEqual(
    getReportSectionLinks('## Findings\n\nFirst.\n\n## Findings\n\nSecond.'),
    [{ id: 'report-section-findings', label: 'Findings' }],
  );
});

test('needs-attention banner names the actual conflicts and recommendations', () => {
  const attention = getReviewAttentionSummary({
    summary: { enhance_sections: 2 },
    consistency: {
      inconsistencies: ['Timeline conflicts with metadata.'],
      recommendations: ['Verify the dated observation.'],
    },
  }, 3);
  const html = renderToStaticMarkup(
    <ReviewStatusBanner status="needs_attention" attention={attention} />,
  );

  assert.match(html, /1 cross-section conflict/);
  assert.match(html, /Operational reuse is blocked by 1 cross-section conflict and 2 sections marked to enhance until an analyst records a disposition\./);
  assert.match(html, /Timeline conflicts with metadata/);
  assert.match(html, /Verify the dated observation/);
});

test('recorded judgment owns operational readiness without erasing machine conflicts', () => {
  const needsRevision = getReviewAttentionSummary({
    consistency: { inconsistencies: ['Timeline conflicts with metadata.'] },
  }, 3, 'needs_revision');
  const accepted = getReviewAttentionSummary({
    consistency: { inconsistencies: ['Timeline conflicts with metadata.'] },
  }, 3, 'accepted');
  const revisionHtml = renderToStaticMarkup(
    <ReviewStatusBanner
      status="needs_attention"
      analystDisposition="needs_revision"
      attention={needsRevision}
    />,
  );
  const acceptedHtml = renderToStaticMarkup(
    <ReviewStatusBanner
      status="needs_attention"
      analystDisposition="accepted"
      attention={accepted}
    />,
  );

  assert.match(revisionHtml, /An analyst kept this evaluation vintage in unresolved work/);
  assert.match(revisionHtml, /Operational reuse remains blocked by 1 cross-section conflict/);
  assert.match(acceptedHtml, /Accepted for reuse/);
  assert.match(acceptedHtml, /An analyst accepted this evaluation vintage with 1 cross-section conflict still recorded below/);
  assert.match(acceptedHtml, /Timeline conflicts with metadata/);
});

test('generation failure copy exonerates the target only when the record proves a route failure', () => {
  const provider = getGenerationFailurePresentation('provider_unavailable', true);
  const evidence = getGenerationFailurePresentation('evidence_unavailable', false);
  const unknown = getGenerationFailurePresentation('unknown', false);

  assert.match(provider.detail, /Your target was not the cause/);
  assert.doesNotMatch(evidence.detail, /Your target was not the cause/);
  assert.match(evidence.detail, /too obscure|more specific name/);
  assert.doesNotMatch(unknown.detail, /Your target was not the cause/);
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
  assert.equal(record.analyst_disposition, 'unreviewed');
  assert.deepEqual(record.disposition_history, []);
  assert.ok(Object.hasOwn(record, 'generation_route'));
  assert.ok(Object.hasOwn(record, 'research_route'));
  assert.ok(Object.hasOwn(record, 'synthesis_route'));
  assert.ok(Object.hasOwn(record, 'evaluation_route'));
  assert.match(record.markdown_content, /Executive Summary/);
});

test('analyst judgment is presented as an append-only evaluation-vintage event', () => {
  const html = renderToStaticMarkup(
    <AnalystDispositionPanel
      report={{
        ...SAMPLE_REPORT,
        analyst_disposition: 'needs_revision',
        current_disposition: {
          id: 'event-1',
          disposition: 'needs_revision',
          note: 'Sources and contradictions checked.',
          evaluation_attempt: 1,
          created_at: '2026-08-14T12:00:00.000Z',
          is_current: true,
        },
        disposition_history: [{
          id: 'event-1',
          disposition: 'needs_revision',
          note: 'Sources and contradictions checked.',
          evaluation_attempt: 1,
          created_at: '2026-08-14T12:00:00.000Z',
          is_current: true,
        }],
      }}
      onRecord={() => undefined}
      onReevaluate={() => undefined}
    />,
  );

  assert.match(html, /Each judgment is appended to the audit history/);
  assert.match(html, /Needs revision/);
  assert.match(html, /checked="" value="needs_revision"/);
  assert.doesNotMatch(html, /value="accepted" checked=""/);
  assert.match(html, /Sources and contradictions checked/);
  assert.match(html, /current vintage/);
  assert.match(html, /Re-run evaluation/);
});
