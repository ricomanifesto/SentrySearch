import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const reportsPagePath = resolve(here, '../src/app/reports/page.tsx');
const apiPath = resolve(here, '../src/lib/api.ts');
const reportsPage = await readFile(reportsPagePath, 'utf8');
const apiClient = await readFile(apiPath, 'utf8');

const expectations = [
  { name: 'keeps reports behind the auth boundary', source: reportsPage, pattern: /<AuthGuard>/ },
  { name: 'anchors the surface as saved intelligence', source: reportsPage, pattern: /Saved intelligence/ },
  { name: 'declares the report review queue surface contract', source: reportsPage, pattern: /data-surface="report-review-queue"/ },
  { name: 'frames saved reports as a review queue', source: reportsPage, pattern: /Review queue/ },
  { name: 'declares each report review record contract', source: reportsPage, pattern: /data-contract="Card\.ReportReviewRecord\.v1"/ },
  { name: 'extracts report record rendering into a named component', source: reportsPage, pattern: /function ReportReviewRecord\(/ },
  { name: 'uses a canonical report record signals collection', source: reportsPage, pattern: /const reportRecordSignals/ },
  { name: 'declares the report record signals contract', source: reportsPage, pattern: /data-contract="Reports\.ReviewRecordSignals\.v1"/ },
  {
    name: 'renders report record signals from the canonical collection',
    source: reportsPage,
    pattern: /reportRecordSignals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.detail/,
  },
  { name: 'shows confidence as analyst confidence', source: reportsPage, pattern: /Analyst confidence/ },
  { name: 'declares the report review queue controls contract', source: reportsPage, pattern: /data-contract="Reports\.ReviewQueueControls\.v1"/ },
  { name: 'uses a canonical review queue controls collection', source: reportsPage, pattern: /const reviewQueueControls/ },
  { name: 'renders queue controls from the canonical collection', source: reportsPage, pattern: /reviewQueueControls\.map/ },
  { name: 'uses queue constraint language for active filters', source: reportsPage, pattern: /queue constraints/ },
  { name: 'does not use generic filter button copy', source: reportsPage, absentPattern: /<FunnelIcon className="h-4 w-4" \/>\s*Filters/ },
  { name: 'does not use generic clear filters copy', source: reportsPage, absentPattern: />\s*Clear filters\s*</ },
  { name: 'uses product-specific open-record action copy', source: reportsPage, pattern: /Open record/ },
  { name: 'uses a non-leaky reports error state', source: reportsPage, pattern: /The saved report list is unavailable/ },
  { name: 'keeps accessible report loading semantics', source: reportsPage, pattern: /role="status" aria-label="Loading reports"/ },
  { name: 'keeps accessible report error semantics', source: reportsPage, pattern: /role="alert"/ },
  { name: 'does not render raw report loading errors', source: reportsPage, absentPattern: /error\?\.message|error\.message/ },
  { name: 'keeps mobile overflow guarded', source: reportsPage, pattern: /overflow-x-hidden/ },
  { name: 'keeps report search copy aligned with listReports fields', source: reportsPage, pattern: /Search by target, category, or threat type/ },
  { name: 'does not advertise unsupported body or tag search', source: reportsPage, absentPattern: /report text, tag|tag, or threat type/ },
  { name: 'passes sort_by from the reports page', source: reportsPage, pattern: /sort_by: filters\.sort_by/ },
  { name: 'passes sort_order from the reports page', source: reportsPage, pattern: /sort_order: filters\.sort_order/ },
  { name: 'adds sort_by to the listReports API query', source: apiClient, pattern: /params\.append\('sort_by', filters\.sort_by\)/ },
  { name: 'adds sort_order to the listReports API query', source: apiClient, pattern: /params\.append\('sort_order', filters\.sort_order\)/ },
  { name: 'does not use fonts below the legible minimum', source: reportsPage, absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', source: reportsPage, absentPattern: /bg-gradient/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Reports surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Reports surface contract check passed (${expectations.length} expectations).`);
