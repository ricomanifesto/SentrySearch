import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const layoutPath = resolve(here, '../src/app/layout.tsx');
const robotsPath = resolve(here, '../src/app/robots.ts');
const sitemapPath = resolve(here, '../src/app/sitemap.ts');
const [layout, robots, sitemap] = await Promise.all([
  readFile(layoutPath, 'utf8'),
  readFile(robotsPath, 'utf8'),
  readFile(sitemapPath, 'utf8'),
]);

const expectations = [
  {
    name: 'uses the live application URL as metadata base',
    source: layout,
    pattern: /metadataBase:\s*new URL\("https:\/\/sentry-search\.vercel\.app"\)/,
  },
  {
    name: 'uses the live application URL as canonical',
    source: layout,
    pattern: /alternates:\s*\{[\s\S]*canonical:\s*"https:\/\/sentry-search\.vercel\.app\/"[\s\S]*\}/,
  },
  {
    name: 'uses the live application URL in Open Graph metadata',
    source: layout,
    pattern: /openGraph:\s*\{[\s\S]*url:\s*"https:\/\/sentry-search\.vercel\.app\/"[\s\S]*\}/,
  },
  {
    name: 'links metadata authorship to Michael Rico',
    source: layout,
    pattern: /authors:\s*\[\{\s*name:\s*"Michael Rico",\s*url:\s*"https:\/\/ricomanifesto\.com\/"\s*\}\]/,
  },
  {
    name: 'uses the evidence-backed public project description',
    source: layout,
    pattern: /description:\s*"SentrySearch turns scattered threat research into source-backed security profiles for malware, attack tools, and targeted technologies, with persistent reports, report-library search, and detection guidance in one workspace\."/,
  },
  {
    name: 'removes the incorrect unhyphenated hostname',
    source: `${layout}\n${robots}\n${sitemap}`,
    absentPattern: /https:\/\/sentrysearch\.vercel\.app/,
  },
  {
    name: 'publishes WebApplication structured data',
    source: layout,
    pattern: /['"]@type['"]:\s*['"]WebApplication['"]/,
  },
  {
    name: 'links structured data authorship to Michael Rico',
    source: layout,
    pattern: /author:\s*\{[\s\S]*name:\s*['"]Michael Rico['"][\s\S]*url:\s*['"]https:\/\/ricomanifesto\.com\/['"]/,
  },
  {
    name: 'declares the application repository in structured data',
    source: layout,
    pattern: /codeRepository:\s*['"]https:\/\/github\.com\/ricomanifesto\/SentrySearch['"]/,
  },
  {
    name: 'serves an origin-level crawler policy',
    source: robots,
    pattern: /sitemap:\s*['"]https:\/\/sentry-search\.vercel\.app\/sitemap\.xml['"]/,
  },
  {
    name: 'allows the public sample route',
    source: robots,
    pattern: /allow:\s*\[['"]\/['"],\s*['"]\/sample['"]\]/,
  },
  {
    name: 'keeps authenticated application routes out of crawler access',
    source: robots,
    pattern: /disallow:\s*\[[\s\S]*['"]\/admin['"][\s\S]*['"]\/auth['"][\s\S]*['"]\/dashboard['"][\s\S]*['"]\/export['"][\s\S]*['"]\/generate['"][\s\S]*['"]\/reports['"][\s\S]*['"]\/search['"][\s\S]*['"]\/settings['"][\s\S]*\]/,
  },
  {
    name: 'includes the public landing page in the sitemap',
    source: sitemap,
    pattern: /url:\s*['"]https:\/\/sentry-search\.vercel\.app\/['"]/,
  },
  {
    name: 'includes the public sample in the sitemap',
    source: sitemap,
    pattern: /url:\s*['"]https:\/\/sentry-search\.vercel\.app\/sample['"]/,
  },
];

const failures = expectations.filter(({ source, pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }
  return Boolean(absentPattern && absentPattern.test(source));
});

if (failures.length > 0) {
  console.error('Metadata surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Metadata surface contract check passed (${expectations.length} expectations).`);
