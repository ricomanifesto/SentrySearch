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
    pattern: /label="Review window"/,
  },
  {
    name: 'shows package-style readiness language for the metric set',
    pattern: /Metric readiness/,
  },
  {
    name: 'avoids unverifiable healthy system claims',
    absentPattern: /System Status|Healthy|All systems operational|Optimized performance/,
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
