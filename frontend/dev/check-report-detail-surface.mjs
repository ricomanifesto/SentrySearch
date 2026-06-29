import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const detailPath = resolve(here, '../src/app/reports/[id]/page.tsx');
const source = await readFile(detailPath, 'utf8');

const expectations = [
  { name: 'keeps report detail behind the auth boundary', pattern: /<AuthGuard>\s*<ReportDetailContent \/>/ },
  { name: 'keeps report fetching inside the guarded detail component', pattern: /api\.getReport\(reportId, true\)/ },
  { name: 'anchors the surface as an intelligence record', pattern: /Intelligence record/ },
  { name: 'uses product-specific narrative framing', pattern: /Intelligence narrative/ },
  { name: 'declares the report detail surface contract', pattern: /data-surface="report-detail-record"/ },
  { name: 'declares the local report detail fixture id', pattern: /const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture'/ },
  { name: 'guards the report detail fixture to development only', pattern: /process\.env\.NODE_ENV === 'development' && reportId === LOCAL_REPORT_DETAIL_FIXTURE_ID/ },
  { name: 'disables report fetching when fixture data is present', pattern: /enabled: !!reportId && !fixtureReport/ },
  { name: 'prevents fixture delete actions from mutating the backend', pattern: /if \(isFixtureRecord\) return;/ },
  { name: 'declares the local report detail fixture contract', pattern: /data-contract="Report\.LocalVisualFixture\.v1"/ },
  { name: 'keeps source transparency visible', pattern: /Source transparency/ },
  { name: 'frames raw technical data as structured extraction data', pattern: /Structured extraction data/ },
  { name: 'contains long structured data output', pattern: /JSON\.stringify\(report\.threat_data, null, 2\)/ },
  { name: 'uses a canonical source review checklist collection', pattern: /const sourceReviewChecklist/ },
  { name: 'renders source review guidance from the canonical checklist', pattern: /sourceReviewChecklist\.map/ },
  { name: 'declares the source review checklist contract', pattern: /data-contract="Report\.SourceReviewChecklist\.v1"/ },
  { name: 'uses a canonical record summary signals collection', pattern: /const recordSummarySignals/ },
  { name: 'renders report summary signals from the canonical collection', pattern: /recordSummarySignals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.detail/ },
  { name: 'declares the report record summary signals contract', pattern: /data-contract="Report\.RecordSummarySignals\.v1"/ },
  { name: 'frames the side rail as review readiness', pattern: /Review readiness/ },
  { name: 'keeps accessible report loading semantics', pattern: /role="status"[\s\S]*aria-label="Loading report record"/ },
  { name: 'keeps accessible report error semantics', pattern: /role="alert"/ },
  { name: 'uses non-leaky report detail error copy', pattern: /This saved record could not be opened/ },
  { name: 'does not render raw loading errors', absentPattern: /error\.message|error\?\.message|String\(error\)/ },
  { name: 'keeps mobile overflow guarded', pattern: /overflow-x-hidden/ },
  { name: 'removes generic not-found heading', absentPattern: /Report Not Found/ },
  { name: 'removes generic report detail heading', absentPattern: />Report Details</ },
  { name: 'does not keep one-off report detail shell colors', absentPattern: /#f7f7f3|#6f755f|#d8d9ce|bg-slate-50/ },
  { name: 'uses product-specific destructive action copy', pattern: /Delete record/ },
  { name: 'uses product-specific download action copy', pattern: /Download markdown/ },
  { name: 'does not use fonts below the legible minimum', absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', absentPattern: /bg-gradient/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Report detail surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Report detail surface contract check passed (${expectations.length} expectations).`);
