import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const landingPath = resolve(here, '../src/app/page.tsx');
const landing = await readFile(landingPath, 'utf8');

const expectations = [
  {
    name: 'declares the landing surface contract',
    source: landing,
    pattern: /data-surface="landing"/,
  },
  {
    name: 'routes authenticated visitors to the dashboard',
    source: landing,
    pattern: /router\.replace\('\/dashboard'\)/,
  },
  {
    name: 'uses product-specific hero copy',
    source: landing,
    pattern: /Threat reports you can actually defend/,
  },
  {
    name: 'frames the product as source-backed threat intelligence',
    source: landing,
    pattern: /Source-backed threat intelligence/,
  },
  {
    name: 'offers a no-signup sample report entry point',
    source: landing,
    pattern: /href="\/sample"/,
  },
  {
    name: 'routes the primary action to account creation',
    source: landing,
    pattern: /href="\/auth\/signup"/,
  },
  {
    name: 'keeps mobile overflow guarded',
    source: landing,
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    source: landing,
    absentPattern: /text-xs/,
  },
  {
    name: 'does not use gradient backgrounds',
    source: landing,
    absentPattern: /bg-gradient/,
  },
  {
    name: 'does not advertise a fabricated generation-time SLA',
    source: landing,
    absentPattern: /2-5 min|30-60s/,
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
  console.error('Landing surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Landing surface contract check passed (${expectations.length} expectations).`);
