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
    pattern: /<AuthGuard>\s*<SearchWorkspace \/>\s*<\/AuthGuard>/,
  },
  {
    name: 'keeps search data queries inside the guarded workspace',
    source: searchPage,
    pattern: /function SearchWorkspace\(\)[\s\S]*useQuery\(/,
  },
  {
    name: 'keeps the search input controlled for clear search',
    source: searchPage,
    pattern: /value={searchInput}[\s\S]*onChange={handleSearchInputChange}/,
  },
  {
    name: 'cancels stale debounced search updates when clearing input',
    source: searchPage,
    pattern: /useEffect\(\(\) => \{[\s\S]*window\.setTimeout[\s\S]*searchInput[\s\S]*return \(\) => window\.clearTimeout\(timeoutId\);[\s\S]*\}, \[searchInput\]\)/,
  },
  {
    name: 'uses the saved intelligence search workspace language',
    source: searchPage,
    pattern: /Search workspace/,
  },
  {
    name: 'declares the search review workspace surface contract',
    source: searchPage,
    pattern: /data-surface="search-review-workspace"/,
  },
  {
    name: 'frames search controls as a query bench',
    source: searchPage,
    pattern: /Query bench/,
  },
  {
    name: 'frames matching results as a review docket',
    source: searchPage,
    pattern: /Review docket/,
  },
  {
    name: 'shows active constraints as workbench constraints',
    source: searchPage,
    pattern: /workbench constraints/,
  },
  {
    name: 'declares each search result record contract',
    source: searchPage,
    pattern: /data-contract="Card\.SearchResultRecord\.v1"/,
  },
  {
    name: 'frames results as analyst confidence',
    source: searchPage,
    pattern: /Analyst confidence/,
  },
  {
    name: 'frames result metadata as decision signals',
    source: searchPage,
    pattern: /Decision signals/,
  },
  {
    name: 'keeps provenance review posture bounded to available detail context',
    source: searchPage,
    pattern: /Provenance review/,
  },
  {
    name: 'uses inspection brief language for record actions',
    source: searchPage,
    pattern: /Inspection brief/,
  },
  {
    name: 'uses product-specific open-record action copy',
    source: searchPage,
    pattern: /Open intelligence record/,
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
    name: 'does not overstate provenance availability for every result',
    source: searchPage,
    absentPattern: /verify sources|sources, tags, and narrative available|Source context preserved/,
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
