import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const samplePath = resolve(here, '../src/app/sample/page.tsx');
const sample = await readFile(samplePath, 'utf8');

const expectations = [
  {
    name: 'declares the sample-report surface contract',
    source: sample,
    pattern: /data-surface="sample-report"/,
  },
  {
    name: 'labels the page as a sample',
    source: sample,
    pattern: /Sample report/,
  },
  {
    name: 'states that no account is required',
    source: sample,
    pattern: /no account needed/,
  },
  {
    name: 'frames the content as a threat-intelligence report',
    source: sample,
    pattern: /Threat intelligence report/,
  },
  {
    name: 'ties findings to their sources',
    source: sample,
    pattern: /Sources/,
  },
  {
    name: 'uses monospace for source and identifier detail',
    source: sample,
    pattern: /font-mono/,
  },
  {
    name: 'routes the call to action to account creation',
    source: sample,
    pattern: /href="\/auth\/signup"/,
  },
  {
    name: 'offers a path back to the public home',
    source: sample,
    pattern: /href="\/"/,
  },
  {
    name: 'does not gate the public sample behind the auth boundary',
    source: sample,
    absentPattern: /AuthGuard/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    source: sample,
    absentPattern: /text-xs/,
  },
  {
    name: 'does not advertise a fabricated generation-time SLA',
    source: sample,
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
  console.error('Sample surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Sample surface contract check passed (${expectations.length} expectations).`);
