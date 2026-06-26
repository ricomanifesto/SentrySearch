#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const packageJson = JSON.parse(
  readFileSync(resolve(process.cwd(), 'package.json'), 'utf8'),
);

const defaultPageExtensions = ['tsx', 'ts', 'jsx', 'js'];
const nextConfigFiles = [
  'next.config.ts',
  'next.config.mjs',
  'next.config.js',
  'next.config.cjs',
];

const routeSurfaces = [
  {
    route: '/',
    page: 'src/app/page.tsx',
    script: 'check:dashboard-surface',
    guard: 'dev/check-dashboard-surface.mjs',
  },
  {
    route: '/admin',
    page: 'src/app/admin/page.tsx',
    script: 'check:admin-surface',
    guard: 'dev/check-admin-surface.mjs',
  },
  {
    route: '/analytics',
    page: 'src/app/analytics/page.tsx',
    script: 'check:analytics-surface',
    guard: 'dev/check-analytics-surface.mjs',
  },
  {
    route: '/auth/signin',
    page: 'src/app/auth/signin/page.tsx',
    script: 'check:auth-surface',
    guard: 'dev/check-auth-surface.mjs',
  },
  {
    route: '/auth/signup',
    page: 'src/app/auth/signup/page.tsx',
    script: 'check:auth-surface',
    guard: 'dev/check-auth-surface.mjs',
  },
  {
    route: '/export',
    page: 'src/app/export/page.tsx',
    script: 'check:export-surface',
    guard: 'dev/check-export-surface.mjs',
  },
  {
    route: '/generate',
    page: 'src/app/generate/page.tsx',
    script: 'check:generate-surface',
    guard: 'dev/check-generate-surface.mjs',
  },
  {
    route: '/reports',
    page: 'src/app/reports/page.tsx',
    script: 'check:reports-surface',
    guard: 'dev/check-reports-surface.mjs',
  },
  {
    route: '/reports/[id]',
    page: 'src/app/reports/[id]/page.tsx',
    script: 'check:report-detail-surface',
    guard: 'dev/check-report-detail-surface.mjs',
  },
  {
    route: '/search',
    page: 'src/app/search/page.tsx',
    script: 'check:search-surface',
    guard: 'dev/check-search-surface.mjs',
  },
  {
    route: '/settings',
    page: 'src/app/settings/page.tsx',
    script: 'check:settings-surface',
    guard: 'dev/check-settings-surface.mjs',
  },
];

const failures = [];
const routePageRoot = resolve(process.cwd(), 'src/app');
const registeredPages = new Set(routeSurfaces.map(({ page }) => page));

function readNextConfig() {
  for (const configFile of nextConfigFiles) {
    const configPath = resolve(process.cwd(), configFile);
    if (existsSync(configPath)) {
      return {
        file: configFile,
        source: readFileSync(configPath, 'utf8'),
      };
    }
  }

  return null;
}

function readPageExtensions() {
  const nextConfig = readNextConfig();
  if (!nextConfig) {
    return defaultPageExtensions;
  }

  const pageExtensionsMatch = nextConfig.source.match(/pageExtensions\s*:\s*\[([\s\S]*?)\]/m);
  if (!pageExtensionsMatch) {
    return defaultPageExtensions;
  }

  const extensions = Array.from(
    pageExtensionsMatch[1].matchAll(/['"]([A-Za-z0-9]+)['"]/g),
    ([, extension]) => extension,
  );

  if (extensions.length === 0) {
    failures.push(`- ${nextConfig.file} pageExtensions must list at least one extension`);
    return [];
  }

  return extensions;
}

function routePath(filePath) {
  return relative(process.cwd(), filePath).replaceAll('\\', '/');
}

const pageExtensions = new Set(readPageExtensions());

function isRoutePage(entry) {
  const match = entry.match(/^page\.([A-Za-z0-9]+)$/);
  return Boolean(match && pageExtensions.has(match[1]));
}

function listRoutePages(directory) {
  return readdirSync(directory)
    .flatMap((entry) => {
      const entryPath = join(directory, entry);
      if (statSync(entryPath).isDirectory()) {
        return listRoutePages(entryPath);
      }

      return isRoutePage(entry) ? [routePath(entryPath)] : [];
    })
    .sort();
}

for (const { route, page } of routeSurfaces) {
  const extension = page.match(/\.([A-Za-z0-9]+)$/)?.[1];
  if (!extension || !pageExtensions.has(extension)) {
    failures.push(`- ${route}: registered page ${page} does not use a supported Next page extension`);
  }
}

for (const page of listRoutePages(routePageRoot)) {
  if (!registeredPages.has(page)) {
    failures.push(`- ${page}: missing route surface registry entry`);
  }
}

for (const { route, page, script, guard } of routeSurfaces) {
  const pagePath = resolve(process.cwd(), page);
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

  if (!existsSync(resolve(process.cwd(), guard))) {
    failures.push(`- ${route}: missing guard file ${guard}`);
  }
}

if (!packageJson.scripts?.['check:surface-coverage']) {
  failures.push('- missing package script check:surface-coverage');
}

if (failures.length > 0) {
  console.error(`Surface coverage check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Surface coverage check passed (${routeSurfaces.length} route surfaces).`);
