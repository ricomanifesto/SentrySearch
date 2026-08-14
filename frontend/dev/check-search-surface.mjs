import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const searchPage = await readFile(resolve(here, '../src/app/search/page.tsx'), 'utf8');

const expectations = [
  { name: 'retires the duplicate search workspace', source: searchPage, pattern: /redirect\(['"]\/reports['"]\)/ },
  { name: 'does not retain a second report-query interface', source: searchPage, absentPattern: /useQuery|searchReports|AuthGuard|Search workspace/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Search surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Search surface contract check passed (${expectations.length} expectations).`);
