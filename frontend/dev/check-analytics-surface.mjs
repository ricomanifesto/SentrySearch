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
    name: 'preserves the dashboard fallback query',
    pattern: /api\.getDashboardAnalytics\(\)/,
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
    name: 'shows readiness language for the metric set',
    pattern: /Metric readiness/,
  },
  {
    name: 'declares the analytics metric signal strip contract',
    pattern: /data-contract="Analytics\.MetricSignalStrip\.v1"/,
  },
  {
    name: 'uses a canonical analytics metric signals collection',
    pattern: /const metricSignals = \[[\s\S]*label: 'Saved intelligence'[\s\S]*label: 'Average confidence'[\s\S]*label: 'Activity cadence'[\s\S]*label: 'Metric readiness'/,
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
    name: 'only reports a completion rate when reports exist',
    pattern: /stats\.total_reports > 0[\s\S]*completed without retry/,
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
    name: 'uses confidence language for activity scores',
    pattern: /Confidence:/,
  },
  {
    name: 'frames threat distribution as a coverage map',
    pattern: /Threat coverage map/,
  },
  {
    name: 'uses triage language for empty threat coverage',
    pattern: /Coverage appears after reports classify threat patterns/,
  },
  {
    name: 'uses the selected analytics period for the report-window count',
    pattern: /reports_period:[\s\S]*overview\.reports_last_30d[\s\S]*overview\.reports_last_7d[\s\S]*selected window/,
  },
  {
    name: 'counts only the recent activity rows rendered on the page',
    pattern: /const shownRecentActivity = recentActivity\.slice\(0, 5\);[\s\S]*value: shownRecentActivity\.length[\s\S]*\{shownRecentActivity\.map/,
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
