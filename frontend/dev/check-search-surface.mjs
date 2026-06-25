import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const searchPagePath = resolve(here, '../src/app/search/page.tsx');
const apiPath = resolve(here, '../src/lib/api.ts');
const searchPage = await readFile(searchPagePath, 'utf8');
const apiClient = await readFile(apiPath, 'utf8');

const expectations = [
  {
    name: 'keeps search behind the auth boundary',
    source: searchPage,
    pattern: /<AuthGuard>/,
  },
  {
    name: 'uses the saved intelligence search workspace language',
    source: searchPage,
    pattern: /Search workspace/,
  },
  {
    name: 'routes search through the canonical API client',
    source: searchPage,
    pattern: /api\.searchReports\(/,
  },
  {
    name: 'keeps search copy aligned with supported fields',
    source: searchPage,
    pattern: /Search by target, category, or threat type/,
  },
  {
    name: 'does not render the old placeholder',
    source: searchPage,
    absentPattern: /coming in Phase 3/,
  },
  {
    name: 'keeps accessible search loading semantics',
    source: searchPage,
    pattern: /role="status" aria-label="Searching saved intelligence"/,
  },
  {
    name: 'keeps accessible search error semantics',
    source: searchPage,
    pattern: /role="alert"/,
  },
  {
    name: 'uses a non-leaky search error state',
    source: searchPage,
    pattern: /Saved intelligence search could not be completed/,
  },
  {
    name: 'does not render raw search loading errors',
    source: searchPage,
    absentPattern: /error\?\.message|error\.message/,
  },
  {
    name: 'keeps mobile overflow guarded',
    source: searchPage,
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'passes sort controls to searchReports',
    source: searchPage,
    pattern: /sort_by: filters\.sortBy[\s\S]*sort_order: filters\.sortOrder/,
  },
  {
    name: 'adds sort_by to the searchReports API query',
    source: apiClient,
    pattern: /params\.append\('sort_by', sort\.sort_by\)/,
  },
  {
    name: 'adds sort_order to the searchReports API query',
    source: apiClient,
    pattern: /params\.append\('sort_order', sort\.sort_order\)/,
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
  console.error('Search surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Search surface contract check passed (${expectations.length} expectations).`);
