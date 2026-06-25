import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = resolve(here, '../src/app/generate/page.tsx');
const source = await readFile(pagePath, 'utf8');

const expectations = [
  {
    name: 'keeps the report generation route state owner client-side',
    pattern: /'use client';/,
  },
  {
    name: 'keeps the report creation API boundary intact',
    pattern: /api\.createReport\(data\)/,
  },
  {
    name: 'keeps generated reports routed to the saved report view',
    pattern: /router\.push\(`\/reports\/\$\{result\.report_id\}`\)/,
  },
  {
    name: 'uses product-specific target guidance',
    pattern: /ShadowPad, Cobalt Strike, SAP NetWeaver/,
  },
  {
    name: 'anchors the surface as a report workspace',
    pattern: /Report workspace/,
  },
  {
    name: 'keeps accessible error alert semantics',
    pattern: /role="alert"/,
  },
  {
    name: 'keeps the generation error state generic',
    pattern: /The report could not be generated\. Check the target and try again\./,
  },
  {
    name: 'does not render raw mutation errors',
    absentPattern: /error\?\.message|error\.message/,
  },
  {
    name: 'keeps accessible async status semantics',
    pattern: /role="status"/,
  },
  {
    name: 'keeps the primary action mobile-safe',
    pattern: /whitespace-normal/,
  },
  {
    name: 'keeps mobile layout overflow guarded',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps report quality guidance visible',
    pattern: /Report quality checks/,
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
  console.error('Generate surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Generate surface contract check passed (${expectations.length} expectations).`);
