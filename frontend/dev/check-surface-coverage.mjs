#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  isRoutableAppDirectory,
  isRoutePage,
  pageFileNames,
  readPageExtensions,
  routePath,
  routeSurfaces,
  routeSurfaceUsesSupportedPageFile,
} from './surface-route-contract.mjs';

const projectRoot = process.cwd();

const packageJson = JSON.parse(
  readFileSync(resolve(projectRoot, 'package.json'), 'utf8'),
);

const failures = [];
const routePageRoot = resolve(projectRoot, 'src/app');
const registeredPages = new Set(routeSurfaces.map(({ page }) => page));
const pageExtensionResult = readPageExtensions(projectRoot);
const supportedPageFileNames = pageFileNames(pageExtensionResult.extensions);
const surfaceCoverageScript = 'check:surface-coverage';
const surfaceCoverageCommand = 'node dev/run-surface-checks.mjs';

function listRoutePages(directory) {
  return readdirSync(directory)
    .flatMap((entry) => {
      const entryPath = join(directory, entry);
      if (statSync(entryPath).isDirectory()) {
        if (!isRoutableAppDirectory(entry)) {
          return [];
        }

        return listRoutePages(entryPath);
      }

      return isRoutePage(entry, supportedPageFileNames) ? [routePath(projectRoot, entryPath)] : [];
    })
    .sort();
}

if (pageExtensionResult.error) {
  failures.push(pageExtensionResult.error);
}

for (const { route, page } of routeSurfaces) {
  if (!routeSurfaceUsesSupportedPageFile(page, supportedPageFileNames)) {
    failures.push(`- ${route}: registered page ${page} does not use a supported Next page extension`);
  }
}

for (const page of listRoutePages(routePageRoot)) {
  if (!registeredPages.has(page)) {
    failures.push(`- ${page}: missing route surface registry entry`);
  }
}

for (const { route, page, script, guard } of routeSurfaces) {
  const pagePath = resolve(projectRoot, page);
  if (!existsSync(pagePath)) {
    failures.push(`- ${route}: missing route page ${page}`);
    continue;
  }

  const command = packageJson.scripts?.[script];
  if (!command) {
    failures.push(`- ${route}: missing package script ${script}`);
    continue;
  }

  const expectedCommand = `node ${guard}`;
  if (command !== expectedCommand) {
    failures.push(`- ${route}: ${script} must run ${expectedCommand}`);
    continue;
  }

  if (!existsSync(resolve(projectRoot, guard))) {
    failures.push(`- ${route}: missing guard file ${guard}`);
  }
}

if (!packageJson.scripts?.[surfaceCoverageScript]) {
  failures.push(`- missing package script ${surfaceCoverageScript}`);
} else if (packageJson.scripts[surfaceCoverageScript] !== surfaceCoverageCommand) {
  failures.push(`- ${surfaceCoverageScript} must run ${surfaceCoverageCommand}`);
}

if (!existsSync(resolve(projectRoot, 'dev/run-surface-checks.mjs'))) {
  failures.push('- missing surface coverage runner dev/run-surface-checks.mjs');
}

if (failures.length > 0) {
  console.error(`Surface coverage check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Surface coverage check passed (${routeSurfaces.length} route surfaces).`);
