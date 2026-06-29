import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dashboardPath = resolve(here, '../src/app/dashboard/page.tsx');
const activityFeedPath = resolve(here, '../src/components/ActivityFeed.tsx');
const navigationPath = resolve(here, '../src/components/layout/Navigation.tsx');
const dashboard = await readFile(dashboardPath, 'utf8');
const activityFeed = await readFile(activityFeedPath, 'utf8');
const navigation = await readFile(navigationPath, 'utf8');

const expectations = [
  {
    name: 'keeps the dashboard route state owner client-side',
    source: dashboard,
    pattern: /'use client';/,
  },
  {
    name: 'keeps the authenticated dashboard behind the auth boundary',
    source: dashboard,
    pattern: /<AuthGuard>/,
  },
  {
    name: 'declares the dashboard workspace surface contract',
    source: dashboard,
    pattern: /data-surface="dashboard-workspace"/,
  },
  {
    name: 'labels the dashboard navigation as the briefing surface',
    source: navigation,
    pattern: /name: 'Briefing', href: '\/dashboard'/,
  },
  {
    name: 'declares the primary investigation action contract',
    source: dashboard,
    pattern: /data-contract="Action\.PrimaryInvestigation\.v1"/,
  },
  {
    name: 'uses product-specific generation action copy',
    source: dashboard,
    pattern: /Generate intelligence/,
  },
  {
    name: 'uses product-specific search action copy',
    source: dashboard,
    pattern: /Search intelligence/,
  },
  {
    name: 'uses product-specific saved report review action copy',
    source: dashboard,
    pattern: /Review saved reports/,
  },
  {
    name: 'declares the dashboard briefing signal strip contract',
    source: dashboard,
    pattern: /data-contract="Dashboard\.BriefingSignalStrip\.v1"/,
  },
  {
    name: 'uses a canonical briefing signals collection',
    source: dashboard,
    pattern: /const briefingSignals = \[[\s\S]*label: 'Intelligence library'[\s\S]*label: 'Briefed this week'[\s\S]*label: 'Analyst confidence'/,
  },
  {
    name: 'renders briefing signals from the canonical collection',
    source: dashboard,
    pattern: /briefingSignals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.detail/,
  },
  {
    name: 'frames recent reports as an intelligence review queue',
    source: dashboard,
    pattern: /Review queue/,
  },
  {
    name: 'uses an honest empty state for the review queue',
    source: dashboard,
    pattern: /Generate your first report to start the review queue/,
  },
  {
    name: 'frames threat distribution as a coverage map',
    source: dashboard,
    pattern: /Coverage map/,
  },
  {
    name: 'declares the dashboard threat coverage map contract',
    source: dashboard,
    pattern: /data-contract="Dashboard\.ThreatCoverageMap\.v1"/,
  },
  {
    name: 'uses a canonical threat coverage row builder',
    source: dashboard,
    pattern: /function buildThreatCoverageRows/,
  },
  {
    name: 'limits threat coverage rows through a named policy',
    source: dashboard,
    pattern: /THREAT_COVERAGE_ROW_LIMIT/,
  },
  {
    name: 'renders threat coverage rows from the canonical helper',
    source: dashboard,
    pattern: /threatCoverageRows\.map/,
  },
  {
    name: 'uses analyst triage language for the threat mix empty state',
    source: dashboard,
    pattern: /Coverage appears once reports classify threat patterns/,
  },
  {
    name: 'uses non-leaky analytics error copy',
    source: dashboard,
    pattern: /The briefing could not refresh/,
  },
  {
    name: 'does not expose local API URLs in user-facing error copy',
    source: dashboard,
    absentPattern: /NEXT_PUBLIC_API_URL|localhost:8001|API server/,
  },
  {
    name: 'keeps mobile overflow guarded',
    source: dashboard,
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    source: dashboard,
    absentPattern: /text-xs/,
  },
  {
    name: 'does not use gradient backgrounds',
    source: dashboard,
    absentPattern: /bg-gradient/,
  },
  {
    name: 'uses product-specific activity feed title copy',
    source: activityFeed,
    pattern: /Activity trail/,
  },
  {
    name: 'declares the dashboard activity trail contract',
    source: activityFeed,
    pattern: /data-contract="Dashboard\.ActivityTrail\.v1"/,
  },
  {
    name: 'uses a canonical activity trail row builder',
    source: activityFeed,
    pattern: /function buildActivityTrailRows/,
  },
  {
    name: 'uses product-specific activity error copy',
    source: activityFeed,
    pattern: /Activity trail is unavailable right now/,
  },
  {
    name: 'uses product-specific empty activity copy',
    source: activityFeed,
    pattern: /Activity appears after reports are generated, opened, exported, or retired/,
  },
  {
    name: 'does not dump raw activity metadata as key-value badges',
    source: activityFeed,
    absentPattern: /Object\.entries\(activity\.metadata[\s\S]*<Badge key=\{key\}[\s\S]*\{key\}: \{String\(value\)\}/,
  },
  {
    name: 'does not show IP-address demo activity on the briefing surface',
    source: activityFeed,
    absentPattern: /IP 203\.0\.113\.42|192\.168\.1\.100|ip_address/,
  },
];

const failures = expectations.filter(({ source, pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }

  if (absentPattern && absentPattern.test(source)) {
    return true;
  }

  return false;
});

if (failures.length > 0) {
  console.error('Dashboard surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Dashboard surface contract check passed (${expectations.length} expectations).`);
