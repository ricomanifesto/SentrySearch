#!/usr/bin/env node

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import {
  normalizeRoutePath,
  parsePageExtensions,
  routeSurfaces,
} from './surface-route-contract.mjs';

const devDir = dirname(fileURLToPath(import.meta.url));
const checkerPath = join(devDir, 'check-surface-coverage.mjs');

function writeFixtureFile(root, filePath, content = '') {
  const absolutePath = join(root, filePath);
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content);
}

function createFixture() {
  const root = mkdtempSync(join(tmpdir(), 'sentrysearch-surface-coverage-'));
  const scripts = Object.fromEntries(
    routeSurfaces.map(({ script, guard }) => [script, `node ${guard}`]),
  );

  scripts['check:surface-coverage'] = 'node dev/run-surface-checks.mjs';

  writeFixtureFile(
    root,
    'package.json',
    `${JSON.stringify({ private: true, scripts }, null, 2)}\n`,
  );

  for (const { page, guard } of routeSurfaces) {
    writeFixtureFile(root, page, 'export default function Page() { return null; }\n');
    writeFixtureFile(root, guard, '#!/usr/bin/env node\n');
  }
  writeFixtureFile(root, 'dev/run-surface-checks.mjs', '#!/usr/bin/env node\n');

  return root;
}

function runChecker(root) {
  return spawnSync(process.execPath, [checkerPath], {
    cwd: root,
    encoding: 'utf8',
  });
}

function assertPass(name, result) {
  if (result.status !== 0) {
    throw new Error(`${name} failed unexpectedly:\n${result.stdout}${result.stderr}`);
  }
}

function assertFailIncludes(name, result, expectedText) {
  if (result.status === 0 || !`${result.stdout}${result.stderr}`.includes(expectedText)) {
    throw new Error(`${name} did not fail with ${expectedText}:\n${result.stdout}${result.stderr}`);
  }
}

function withFixture(name, test) {
  const root = createFixture();
  try {
    test(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  console.log(`✓ ${name}`);
}

withFixture('passes the registered route surface fixture', (root) => {
  assertPass('registered route surface fixture', runChecker(root));
});

withFixture('skips App Router private folders', (root) => {
  writeFixtureFile(
    root,
    'src/app/_components/example/page.tsx',
    'export default function Example() { return null; }\n',
  );

  assertPass('private folder route fixture', runChecker(root));
});

withFixture('skips App Router named slots', (root) => {
  writeFixtureFile(
    root,
    'src/app/@modal/example/page.tsx',
    'export default function ModalExample() { return null; }\n',
  );

  assertPass('parallel route slot fixture', runChecker(root));
});

withFixture('fails for unregistered supported route pages', (root) => {
  writeFixtureFile(
    root,
    'src/app/unregistered/page.ts',
    'export default function Unregistered() { return null; }\n',
  );

  assertFailIncludes(
    'unregistered route page fixture',
    runChecker(root),
    'src/app/unregistered/page.ts: missing route surface registry entry',
  );
});

withFixture('fails when a route script points at the wrong guard', (root) => {
  const packageJsonPath = resolve(root, 'package.json');
  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  packageJson.scripts['check:generate-surface'] = 'node dev/check-export-surface.mjs';
  writeFixtureFile(root, 'package.json', `${JSON.stringify(packageJson, null, 2)}\n`);

  assertFailIncludes(
    'wrong guard fixture',
    runChecker(root),
    '/generate: check:generate-surface must run node dev/check-generate-surface.mjs',
  );
});

withFixture('fails when the coverage entrypoint is bypassed', (root) => {
  const packageJsonPath = resolve(root, 'package.json');
  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  packageJson.scripts['check:surface-coverage'] = 'node dev/check-surface-coverage.mjs';
  writeFixtureFile(root, 'package.json', `${JSON.stringify(packageJson, null, 2)}\n`);

  assertFailIncludes(
    'coverage entrypoint bypass fixture',
    runChecker(root),
    'check:surface-coverage must run node dev/run-surface-checks.mjs',
  );
});

const parsedDottedExtensions = parsePageExtensions("export default { pageExtensions: ['page.tsx'] }");
if (parsedDottedExtensions?.[0] !== 'page.tsx') {
  throw new Error('dotted pageExtensions entries must be parsed without truncation');
}
console.log('✓ parses dotted pageExtensions');

const normalizedWindowsPath = normalizeRoutePath('src\\app\\reports\\page.tsx');
if (normalizedWindowsPath !== 'src/app/reports/page.tsx') {
  throw new Error('Windows route paths must normalize to slash-delimited paths');
}
console.log('✓ normalizes Windows route paths');

console.log('Surface coverage regression checks passed.');
