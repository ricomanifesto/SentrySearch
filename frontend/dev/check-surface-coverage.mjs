#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const packageJson = JSON.parse(
  readFileSync(resolve(process.cwd(), 'package.json'), 'utf8'),
);

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

function routePath(filePath) {
  return relative(process.cwd(), filePath).replaceAll('\\', '/');
}

function listRoutePages(directory) {
  return readdirSync(directory)
    .flatMap((entry) => {
      const entryPath = join(directory, entry);
      if (statSync(entryPath).isDirectory()) {
        return listRoutePages(entryPath);
      }

      return entry === 'page.tsx' ? [routePath(entryPath)] : [];
    })
    .sort();
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
