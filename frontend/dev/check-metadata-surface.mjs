import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const layoutPath = resolve(here, '../src/app/layout.tsx');
const layout = await readFile(layoutPath, 'utf8');

const expectations = [
  {
    name: 'uses the live application URL as metadata base',
    pattern: /metadataBase:\s*new URL\("https:\/\/sentry-search\.vercel\.app"\)/,
  },
  {
    name: 'uses the live application URL as canonical',
    pattern: /alternates:\s*\{[\s\S]*canonical:\s*"https:\/\/sentry-search\.vercel\.app\/"[\s\S]*\}/,
  },
  {
    name: 'uses the live application URL in Open Graph metadata',
    pattern: /openGraph:\s*\{[\s\S]*url:\s*"https:\/\/sentry-search\.vercel\.app\/"[\s\S]*\}/,
  },
  {
    name: 'links metadata authorship to Michael Rico',
    pattern: /authors:\s*\[\{\s*name:\s*"Michael Rico",\s*url:\s*"https:\/\/ricomanifesto\.com\/"\s*\}\]/,
  },
  {
    name: 'uses the evidence-backed public project description',
    pattern: /description:\s*"SentrySearch turns scattered threat research into searchable security profiles for malware, attack tools, and targeted technologies, with persistent reports, hybrid search, and detection guidance in one workspace\."/,
  },
  {
    name: 'removes the incorrect unhyphenated hostname',
    absentPattern: /https:\/\/sentrysearch\.vercel\.app/,
  },
];

const failures = expectations.filter(({ pattern, absentPattern }) => {
  if (pattern && !pattern.test(layout)) {
    return true;
  }
  return Boolean(absentPattern && absentPattern.test(layout));
});

if (failures.length > 0) {
  console.error('Metadata surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Metadata surface contract check passed (${expectations.length} expectations).`);
