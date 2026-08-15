#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const analyticsPage = readFileSync(
  resolve(process.cwd(), 'src/app/analytics/page.tsx'),
  'utf8',
);
const packageJson = readFileSync(resolve(process.cwd(), 'package.json'), 'utf8');

const expectations = [
  {
    name: 'keeps analytics behind the auth boundary',
    pattern: /<AuthGuard>/,
  },
  {
    name: 'declares the analytics review surface contract',
    pattern: /data-surface="analytics-review"/,
  },
  {
    name: 'preserves the analytics read model query',
    pattern: /api\.getAnalytics\(timeRange\)/,
  },
  {
    name: 'frames the page as an operations review surface',
    pattern: /Intelligence operations review/,
  },
  {
    name: 'frames the metric set as operations metrics',
    pattern: /Operations metrics/,
  },
  {
    name: 'does not lead with generic analytics dashboard copy',
    absentPattern: /Analytics Dashboard|Comprehensive insights into threat intelligence operations/,
  },
  {
    name: 'uses accessible loading status semantics',
    pattern: /role="status"[\s\S]*Preparing operations metrics/,
  },
  {
    name: 'uses accessible error alert semantics',
    pattern: /role="alert"[\s\S]*Operations metrics are not available right now/,
  },
  {
    name: 'does not render raw analytics error details',
    absentPattern: /error\.message|error\?\.message|String\(error\)/,
  },
  {
    name: 'labels the time window control',
    pattern: /Review window/,
  },
  {
    name: 'shows unresolved analyst work in the metric set',
    pattern: /Unresolved work[\s\S]*accepted[\s\S]*generation failures/,
  },
  {
    name: 'declares the analytics metric signal strip contract',
    pattern: /data-contract="Analytics\.MetricSignalStrip\.v1"/,
  },
  {
    name: 'uses a canonical analytics metric signals collection',
    pattern: /const metricSignals = \[[\s\S]*label: 'Reports in window'[\s\S]*label: 'Content quality'[\s\S]*label: 'Unresolved work'[\s\S]*label: 'Generation completion'/,
  },
  {
    name: 'renders analytics metric signals from the canonical collection',
    pattern: /metricSignals\.map\(\(metric\)[\s\S]*metric\.label[\s\S]*metric\.value[\s\S]*metric\.detail/,
  },
  {
    name: 'does not fabricate a default success rate',
    absentPattern: /success_rate[^\n]*\|\|\s*0\.95/,
  },
  {
    name: 'keeps generation completion separate from content quality',
    pattern: /generation_completion_rate == null[\s\S]*terminal generation records/,
  },
  {
    name: 'does not fabricate a default activity confidence score',
    absentPattern: /quality_score \|\| 4\.0/,
  },
  {
    name: 'does not keep repeated hand-built metric cards',
    absentPattern: /<Card /,
  },
  {
    name: 'frames recent activity as a review timeline',
    pattern: /Review timeline/,
  },
  {
    name: 'uses content quality language for activity scores',
    pattern: /Content quality:/,
  },
  {
    name: 'frames threat distribution as a coverage map',
    pattern: /Threat coverage map/,
  },
  {
    name: 'declares the generation route comparison contract',
    pattern: /data-contract="Analytics\.GenerationRouteComparison\.v1"/,
  },
  {
    name: 'exposes typed failure clusters by cause stage route and hour',
    pattern: /data-contract="Analytics\.GenerationFailureEvidence\.v1"[\s\S]*Last stages[\s\S]*Routes[\s\S]*UTC hours/,
  },
  {
    name: 'separates requested fallback and legacy routes',
    pattern: /primary: 'Requested route'[\s\S]*fallback: 'Fallback route'[\s\S]*unrecorded: 'Legacy \/ unrecorded'/,
  },
  {
    name: 'compares quality and runtime without fabricating missing values',
    pattern: /avg_quality_score == null[\s\S]*Content quality not scored[\s\S]*avg_processing_time_ms == null[\s\S]*Runtime not recorded/,
  },
  {
    name: 'marks fallback-built reports in recent activity',
    pattern: /generation_used_fallback === true[\s\S]*Fallback route/,
  },
  {
    name: 'uses human-readable generation failure causes and stages',
    pattern: /Provider route unavailable[\s\S]*Legacy \/ unrecorded cause[\s\S]*Unrecorded stage/,
  },
  {
    name: 'shows analyst disposition in recent activity',
    pattern: /getAnalystDispositionLabel\(activity\.analyst_disposition\)/,
  },
  {
    name: 'shows analyst disposition only for backend-eligible report vintages',
    pattern: /activity\.eligible_for_judgment \? \([\s\S]*getAnalystDispositionLabel/,
  },
  {
    name: 'uses triage language for empty threat coverage',
    pattern: /Coverage appears after reports classify threat patterns/,
  },
  {
    name: 'uses the backend-selected analytics period for the report-window count',
    pattern: /const reportsPeriod = overview\?\.reports_in_period/,
  },
  {
    name: 'renders only the bounded recent activity rows',
    pattern: /const shownRecentActivity = recentActivity\.slice\(0, 5\);[\s\S]*\{shownRecentActivity\.map/,
  },
  {
    name: 'shows route metric denominators and exclusions explicitly',
    pattern: /scored_report_count[\s\S]*runtime_recorded_count/,
  },
  {
    name: 'does not restore the meaningless metric readiness card',
    absentPattern: /Metric readiness|source for this review/,
  },
  {
    name: 'avoids unverifiable healthy system claims',
    absentPattern: /System Status|All systems operational|Optimized performance/,
  },
  {
    name: 'guards the route against horizontal mobile overflow',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps layout containers shrink-safe',
    pattern: /min-w-0/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    absentPattern: /text-xs/,
  },
  {
    name: 'does not use gradient backgrounds',
    absentPattern: /bg-gradient/,
  },
  {
    name: 'registers the analytics surface check script',
    source: packageJson,
    pattern: /"check:analytics-surface": "node dev\/check-analytics-surface\.mjs"/,
  },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source = analyticsPage }) => (
    pattern ? !pattern.test(source) : absentPattern.test(source)
  ))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Analytics surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Analytics surface contract check passed (${expectations.length} expectations).`);
