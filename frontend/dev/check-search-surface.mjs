import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const searchPagePath = resolve(here, '../src/app/search/page.tsx');
const surfaceHeaderPath = resolve(here, '../src/components/ui/SurfaceHeader.tsx');
const apiPath = resolve(here, '../src/lib/api.ts');
const searchPage = await readFile(searchPagePath, 'utf8');
const surfaceHeader = await readFile(surfaceHeaderPath, 'utf8').catch(() => '');
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
    name: 'uses the shared surface header component',
    source: searchPage,
    pattern: /<SurfaceHeader[\s\S]*eyebrow="Search workspace"[\s\S]*title="Find saved intelligence by target and threat context"/,
  },
  {
    name: 'imports the shared surface header component',
    source: searchPage,
    pattern: /import \{ SurfaceHeader \} from '@\/components\/ui\/SurfaceHeader';/,
  },
  {
    name: 'defines the shared surface header contract',
    source: surfaceHeader,
    pattern: /data-contract="Component\.SurfaceHeader\.v1"/,
  },
  {
    name: 'frames search controls as a query bench',
    source: searchPage,
    pattern: /Query bench/,
  },
  {
    name: 'declares the search query workbench controls contract',
    source: searchPage,
    pattern: /data-contract="Search\.QueryWorkbenchControls\.v1"/,
  },
  {
    name: 'uses a canonical query workbench controls collection',
    source: searchPage,
    pattern: /const queryWorkbenchControls/,
  },
  {
    name: 'renders query workbench controls from the canonical collection',
    source: searchPage,
    pattern: /queryWorkbenchControls\.map/,
  },
  {
    name: 'uses workbench constraint language for active search controls',
    source: searchPage,
    pattern: /active workbench/,
  },
  {
    name: 'uses workbench-specific clear action copy',
    source: searchPage,
    pattern: /Clear workbench constraints/,
  },
  {
    name: 'does not use generic clear search copy',
    source: searchPage,
    absentPattern: />\s*Clear search\s*</,
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
    name: 'declares the search result review signals contract',
    source: searchPage,
    pattern: /data-contract="Search\.ResultReviewSignals\.v1"/,
  },
  {
    name: 'uses a canonical result review signals collection',
    source: searchPage,
    pattern: /const resultReviewSignals/,
  },
  {
    name: 'renders result review signals from the canonical collection',
    source: searchPage,
    pattern: /resultReviewSignals\.map/,
  },
  {
    name: 'extracts result record rendering into a named component',
    source: searchPage,
    pattern: /function SearchResultRecord\(/,
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
    name: 'uses review-ready result record action framing',
    source: searchPage,
    pattern: /Review record/,
  },
  {
    name: 'does not keep the old loose result signal grid',
    source: searchPage,
    absentPattern: /mt-3 grid gap-3 sm:grid-cols-2/,
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
    absentPattern: /verify sources|sources, tags, and narrative available|Source context preserved|stored source data/,
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
