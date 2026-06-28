import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const detailPath = resolve(here, '../src/app/reports/[id]/page.tsx');
const source = await readFile(detailPath, 'utf8');

const expectations = [
  {
    name: 'keeps report detail behind the auth boundary',
    pattern: /<AuthGuard>\s*<ReportDetailContent \/>/,
  },
  {
    name: 'keeps report fetching inside the guarded detail component',
    pattern: /function ReportDetailContent\(\{ fixtureReport \}: \{ fixtureReport\?: ReportDetail \}\)[\s\S]*useQuery\(/,
  },
  {
    name: 'anchors the surface as an intelligence record',
    pattern: /intelligence record/,
  },
  {
    name: 'uses product-specific narrative framing',
    pattern: /Intelligence narrative/,
  },
  {
    name: 'declares the report detail surface contract',
    pattern: /data-surface="report-detail-record"/,
  },
  {
    name: 'uses the shared surface header component',
    pattern: /<SurfaceHeader[\s\S]*eyebrow="Intelligence record"/,
  },
  {
    name: 'imports the shared surface header component',
    pattern: /import \{ SurfaceHeader \} from '@\/components\/ui\/SurfaceHeader';/,
  },
  {
    name: 'declares the local report detail fixture id',
    pattern: /const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture'/,
  },
  {
    name: 'guards the report detail fixture to development only',
    pattern: /process\.env\.NODE_ENV === 'development'[\s\S]*reportId === LOCAL_REPORT_DETAIL_FIXTURE_ID/,
  },
  {
    name: 'keeps normal report ids behind the auth boundary',
    pattern: /return isLocalVisualFixture \? \([\s\S]*<ReportDetailContent fixtureReport=\{localReportDetailFixture\} \/>[\s\S]*\) : \([\s\S]*<AuthGuard>[\s\S]*<ReportDetailContent \/>[\s\S]*<\/AuthGuard>/,
  },
  {
    name: 'keeps source transparency visible',
    pattern: /Source context/,
  },
  {
    name: 'frames raw technical data as structured extraction data',
    pattern: /Structured extraction data/,
  },
  {
    name: 'uses a canonical source review checklist contract',
    pattern: /const sourceReviewChecklist = \[[\s\S]*label: 'Narrative review'[\s\S]*label: 'Source transparency'[\s\S]*label: 'Extraction audit'/,
  },
  {
    name: 'renders source review guidance from the canonical checklist',
    pattern: /sourceReviewChecklist\.map\(\(item\)[\s\S]*item\.label[\s\S]*item\.status[\s\S]*item\.description/,
  },
  {
    name: 'declares the source review checklist contract',
    pattern: /data-contract="Report\.SourceReviewChecklist\.v1"/,
  },
  {
    name: 'uses a canonical record summary signals collection',
    pattern: /const recordSummarySignals = \[[\s\S]*label: 'Confidence'[\s\S]*label: 'Category'[\s\S]*label: 'Threat type'[\s\S]*label: 'Generated'/,
  },
  {
    name: 'declares the local report detail fixture contract',
    pattern: /data-contract="Report\.LocalVisualFixture\.v1"/,
  },
  {
    name: 'disables report fetching when fixture data is present',
    pattern: /enabled: !!reportId && !fixtureReport/,
  },
  {
    name: 'prevents fixture delete actions from mutating the backend',
    pattern: /disabled=\{isFixtureRecord \|\| deleteMutation\.isPending\}/,
  },
  {
    name: 'declares the report record summary signals contract',
    pattern: /data-contract="Report\.RecordSummarySignals\.v1"/,
  },
  {
    name: 'renders report summary signals from the canonical collection',
    pattern: /recordSummarySignals\.map\(\(item\)[\s\S]*item\.label[\s\S]*item\.value[\s\S]*item\.detail/,
  },
  {
    name: 'frames the summary strip as record summary signals',
    pattern: /Record summary signals/,
  },
  {
    name: 'frames the side rail as review readiness',
    pattern: /Review readiness/,
  },
  {
    name: 'does not keep disconnected review posture sidebar',
    absentPattern: /<h2 className="text-base font-semibold text-\[#20231f\]">Review posture<\/h2>/,
  },
  {
    name: 'contains long structured data output',
    pattern: /max-h-\[32rem\] overflow-auto/,
  },
  {
    name: 'keeps accessible report loading semantics',
    pattern: /role="status"[\s\S]*aria-label="Loading report record"/,
  },
  {
    name: 'keeps accessible report error semantics',
    pattern: /role="alert"/,
  },
  {
    name: 'uses non-leaky report detail error copy',
    pattern: /This saved intelligence record could not be opened/,
  },
  {
    name: 'keeps mobile overflow guarded',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'removes generic not-found heading',
    absentPattern: /Report Not Found/,
  },
  {
    name: 'removes generic report detail heading',
    absentPattern: /Threat Intelligence Report/,
  },
  {
    name: 'does not render raw loading errors',
    absentPattern: /error\?\.message|error\.message/,
  },
  {
    name: 'does not keep one-off report detail shell colors',
    absentPattern: /bg-\[#f7f7f3\]|text-\[#171915\]/,
  },
  {
    name: 'does not overstate saved source data availability',
    absentPattern: /Source transparency is preserved through|saved report narrative, search tags, and structured technical extraction below/,
  },
  {
    name: 'uses product-specific destructive action copy',
    pattern: /Delete record/,
  },
  {
    name: 'uses product-specific download action copy',
    pattern: /Download markdown/,
  },
];

const failures = expectations.filter(({ pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }

  if (absentPattern && absentPattern.test(source)) {
    return true;
  }

  return false;
});

if (failures.length > 0) {
  console.error('Report detail surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Report detail surface contract check passed (${expectations.length} expectations).`);
