import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const searchPagePath = resolve(here, '../src/app/search/page.tsx');
const apiPath = resolve(here, '../src/lib/api.ts');
const searchPage = await readFile(searchPagePath, 'utf8');
const apiClient = await readFile(apiPath, 'utf8');

const expectations = [
  { name: 'keeps search behind the auth boundary', source: searchPage, pattern: /<AuthGuard>\s*<SearchWorkspace \/>/ },
  { name: 'declares the search workspace surface contract', source: searchPage, pattern: /data-surface="search-review-workspace"/ },
  { name: 'anchors the surface as a search workspace', source: searchPage, pattern: /Search workspace/ },
  { name: 'runs search through the backend search contract', source: searchPage, pattern: /api\.searchReports\(/ },
  { name: 'passes sort_by to the search query', source: searchPage, pattern: /sort_by: filters\.sortBy/ },
  { name: 'passes sort_order to the search query', source: searchPage, pattern: /sort_order: filters\.sortOrder/ },
  { name: 'declares the query workbench controls contract', source: searchPage, pattern: /data-contract="Search\.QueryWorkbenchControls\.v1"/ },
  { name: 'uses a canonical query workbench controls collection', source: searchPage, pattern: /const queryWorkbenchControls/ },
  { name: 'renders workbench controls from the canonical collection', source: searchPage, pattern: /queryWorkbenchControls\.map/ },
  { name: 'uses workbench constraint language for active filters', source: searchPage, pattern: /workbench constraints/ },
  { name: 'extracts result rendering into a named component', source: searchPage, pattern: /function SearchResultRecord\(/ },
  { name: 'declares each search result record contract', source: searchPage, pattern: /data-contract="Card\.SearchResultRecord\.v1"/ },
  { name: 'uses a canonical result review signals collection', source: searchPage, pattern: /const resultReviewSignals/ },
  { name: 'declares the result review signals contract', source: searchPage, pattern: /data-contract="Search\.ResultReviewSignals\.v1"/ },
  {
    name: 'renders result review signals from the canonical collection',
    source: searchPage,
    pattern: /resultReviewSignals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.description/,
  },
  { name: 'shows confidence as analyst confidence', source: searchPage, pattern: /Analyst confidence/ },
  { name: 'keeps search copy aligned with supported fields', source: searchPage, pattern: /Search by target, category, or threat type/ },
  { name: 'does not advertise unsupported full-text search', source: searchPage, absentPattern: /full report text|report body search/ },
  { name: 'uses a non-leaky search error state', source: searchPage, pattern: /Saved intelligence search could not be completed/ },
  { name: 'keeps accessible search loading semantics', source: searchPage, pattern: /role="status" aria-label="Searching saved intelligence"/ },
  { name: 'keeps accessible search error semantics', source: searchPage, pattern: /role="alert"/ },
  { name: 'does not render raw search errors', source: searchPage, absentPattern: /error\?\.message|error\.message/ },
  { name: 'keeps mobile overflow guarded', source: searchPage, pattern: /overflow-x-hidden/ },
  { name: 'keeps layout containers shrink-safe', source: searchPage, pattern: /min-w-0/ },
  { name: 'does not use fonts below the legible minimum', source: searchPage, absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', source: searchPage, absentPattern: /bg-gradient/ },
  { name: 'exposes search sort support in the API client', source: apiClient, pattern: /searchReports/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Search surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Search surface contract check passed (${expectations.length} expectations).`);
