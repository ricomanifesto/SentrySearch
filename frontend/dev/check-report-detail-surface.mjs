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
    pattern: /function ReportDetailContent\(\)[\s\S]*useQuery\(/,
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
