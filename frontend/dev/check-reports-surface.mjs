import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const reportsPagePath = resolve(here, '../src/app/reports/page.tsx');
const apiPath = resolve(here, '../src/lib/api.ts');
const reportsPage = await readFile(reportsPagePath, 'utf8');
const apiClient = await readFile(apiPath, 'utf8');

const expectations = [
  {
    name: 'keeps reports behind the auth boundary',
    source: reportsPage,
    pattern: /<AuthGuard>/,
  },
  {
    name: 'anchors the surface as saved intelligence',
    source: reportsPage,
    pattern: /Saved intelligence/,
  },
  {
    name: 'declares the report review queue surface contract',
    source: reportsPage,
    pattern: /data-surface="report-review-queue"/,
  },
  {
    name: 'declares each report review record contract',
    source: reportsPage,
    pattern: /data-contract="Card\.ReportReviewRecord\.v1"/,
  },
  {
    name: 'surfaces provenance posture in the report queue',
    source: reportsPage,
    pattern: /Provenance posture/,
  },
  {
    name: 'keeps the active sort visible in the report queue',
    source: reportsPage,
    pattern: /Sorted by/,
  },
  {
    name: 'shows confidence as analyst confidence',
    source: reportsPage,
    pattern: /Analyst confidence/,
  },
  {
    name: 'frames saved reports as a review queue',
    source: reportsPage,
    pattern: /Review queue/,
  },
  {
    name: 'uses product-specific open-record action copy',
    source: reportsPage,
    pattern: /Open intelligence record/,
  },
  {
    name: 'keeps source and review affordance visible',
    source: reportsPage,
    pattern: /Sources, tags, and report body/,
  },
  {
    name: 'uses a non-leaky reports error state',
    source: reportsPage,
    pattern: /The saved report list is unavailable/,
  },
  {
    name: 'keeps accessible report loading semantics',
    source: reportsPage,
    pattern: /role="status" aria-label="Loading reports"/,
  },
  {
    name: 'keeps accessible report error semantics',
    source: reportsPage,
    pattern: /role="alert"/,
  },
  {
    name: 'keeps mobile overflow guarded',
    source: reportsPage,
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps report search copy aligned with listReports fields',
    source: reportsPage,
    pattern: /Search by target, category, or threat type/,
  },
  {
    name: 'does not advertise unsupported body or tag search',
    source: reportsPage,
    absentPattern: /report text, tag|tag, or threat type/,
  },
  {
    name: 'passes sort_by from the reports page',
    source: reportsPage,
    pattern: /sort_by: filters\.sort_by/,
  },
  {
    name: 'passes sort_order from the reports page',
    source: reportsPage,
    pattern: /sort_order: filters\.sort_order/,
  },
  {
    name: 'adds sort_by to the listReports API query',
    source: apiClient,
    pattern: /params\.append\('sort_by', filters\.sort_by\)/,
  },
  {
    name: 'adds sort_order to the listReports API query',
    source: apiClient,
    pattern: /params\.append\('sort_order', filters\.sort_order\)/,
  },
  {
    name: 'does not render raw report loading errors',
    source: reportsPage,
    absentPattern: /error\?\.message|error\.message/,
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
  console.error('Reports surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Reports surface contract check passed (${expectations.length} expectations).`);
