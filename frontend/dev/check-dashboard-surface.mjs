import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dashboardPath = resolve(here, '../src/app/dashboard/page.tsx');
const activityFeedPath = resolve(here, '../src/components/ActivityFeed.tsx');
const navigationPath = resolve(here, '../src/components/layout/Navigation.tsx');
const briefingSignalsPath = resolve(here, '../src/components/DashboardBriefingSignals.tsx');
const dashboard = await readFile(dashboardPath, 'utf8');
const activityFeed = await readFile(activityFeedPath, 'utf8');
const navigation = await readFile(navigationPath, 'utf8');
const briefingSignals = await readFile(briefingSignalsPath, 'utf8');

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
    name: 'uses the shared sentinel-shield mark in the application navigation',
    source: navigation,
    pattern: /<Image[\s\S]*src="\/icon\.svg"[\s\S]*alt=""[\s\S]*width=\{32\}[\s\S]*height=\{32\}/,
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
    pattern: /Search and filter reports/,
  },
  {
    name: 'uses product-specific saved report review action copy',
    source: dashboard,
    pattern: /Review saved reports/,
  },
  {
    name: 'declares the dashboard briefing signal strip contract',
    source: briefingSignals,
    pattern: /data-contract="Dashboard\.BriefingSignalStrip\.v1"/,
  },
  {
    name: 'uses a canonical briefing signals collection',
    source: briefingSignals,
    pattern: /const signals = \[[\s\S]*label: 'Intelligence library'[\s\S]*label: 'Completed this week'[\s\S]*label: 'Content quality'/,
  },
  {
    name: 'renders briefing signals from the canonical collection',
    source: briefingSignals,
    pattern: /signals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.detail/,
  },
  {
    name: 'frames recent reports as an intelligence review queue',
    source: dashboard,
    pattern: /Review queue/,
  },
  {
    name: 'uses the current-vintage unresolved-work query on the dashboard',
    source: dashboard,
    pattern: /requires_action: true/,
  },
  {
    name: 'uses an honest empty state for the review queue',
    source: dashboard,
    pattern: /Generate your first report to start the review queue/,
  },
  {
    name: 'shows analyst judgment only for backend-eligible report vintages',
    source: dashboard,
    pattern: /report\.eligible_for_judgment \? \([\s\S]*getAnalystDispositionLabel/,
  },
  {
    name: 'keeps report-load failures distinct from an empty review queue',
    source: dashboard,
    pattern: /Couldn&apos;t load your reports/,
  },
  {
    name: 'offers a retry for a report-load failure',
    source: dashboard,
    pattern: /refetchReports/,
  },
  {
    name: 'does not grade an unscored workspace as zero',
    source: briefingSignals,
    pattern: /No scored reports yet/,
  },
  {
    name: 'does not fall back to a zero confidence score',
    source: dashboard,
    absentPattern: /avg_quality_score\?\.toFixed\(1\) \?\? '0\.0'/,
  },
  {
    name: 'does not restore the briefed overstatement',
    source: briefingSignals,
    absentPattern: /Briefed this week|New intelligence generated/,
  },
  {
    name: 'keeps public auth controls hidden while the session resolves',
    source: navigation,
    pattern: /if \(loading\)[\s\S]*Resolving workspace session[\s\S]*if \(!userLabel\)/,
  },
  {
    name: 'renders loading separately from zero-valued briefing signals',
    source: briefingSignals,
    pattern: /if \(isLoading\)[\s\S]*Loading workspace briefing[\s\S]*const signals/,
  },
  {
    name: 'does not restore the unused admin navigation',
    source: navigation,
    absentPattern: /\/admin|adminNavigation|name: 'Admin'/,
  },
  {
    name: 'gives icon-only account actions accessible names',
    source: navigation,
    pattern: /aria-label="Workspace access"[\s\S]*aria-label="Sign out"/,
  },
  {
    name: 'keeps workspace access and sign out available in the mobile menu',
    source: navigation,
    pattern: /id="mobile-navigation"[\s\S]*Workspace access[\s\S]*Sign out/,
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
    pattern: /Activity appears after a report is generated/,
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
