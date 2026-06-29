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
    pattern: /api\.createReport/,
  },
  {
    name: 'keeps generation behind the authentication boundary',
    pattern: /<AuthGuard>/,
  },
  {
    name: 'declares the generate console surface contract',
    pattern: /data-surface="generate-console"/,
  },
  {
    name: 'uses product-specific generate title copy',
    pattern: /Generate a threat intelligence report/,
  },
  {
    name: 'keeps a target input with a product-specific placeholder',
    pattern: /ShadowPad or SAP NetWeaver/,
  },
  {
    name: 'keeps ML guidance disabled platform-wide',
    pattern: /enable_ml_guidance: false/,
  },
  {
    name: 'does not expose the ML guidance toggle while its service is down',
    absentPattern: /Include detection and mitigation guidance|type="checkbox"/,
  },
  {
    name: 'declares the target seed library contract',
    pattern: /data-contract="Generate\.TargetSeedLibrary\.v1"/,
  },
  {
    name: 'declares the report-includes contract',
    pattern: /data-contract="Generate\.ReportIncludes\.v1"/,
  },
  {
    name: 'sets honest generation-time expectations without a fabricated SLA',
    pattern: /Research and synthesis can take a few minutes/,
  },
  {
    name: 'keeps mobile overflow guarded',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'does not present fabricated tier names as selectable modes',
    absentPattern: /Full intelligence brief|Triage brief|Focused analyst note/,
  },
  {
    name: 'does not advertise fabricated per-tier SLAs',
    absentPattern: /2-5 min|30-60s/,
  },
  {
    name: 'does not expose local API URLs in user-facing copy',
    absentPattern: /NEXT_PUBLIC_API_URL|localhost:8001/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    absentPattern: /text-xs/,
  },
  {
    name: 'does not use gradient backgrounds',
    absentPattern: /bg-gradient/,
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
