import { existsSync, readFileSync } from 'node:fs';
import { basename, relative, resolve } from 'node:path';

export const defaultPageExtensions = ['tsx', 'ts', 'jsx', 'js'];

export const nextConfigFiles = [
  'next.config.ts',
  'next.config.mjs',
  'next.config.js',
  'next.config.cjs',
];

export const routeSurfaces = [
  {
    route: '/',
    page: 'src/app/page.tsx',
    script: 'check:landing-surface',
    guard: 'dev/check-landing-surface.mjs',
  },
  {
    route: '/dashboard',
    page: 'src/app/dashboard/page.tsx',
    script: 'check:dashboard-surface',
    guard: 'dev/check-dashboard-surface.mjs',
  },
  {
    route: '/sample',
    page: 'src/app/sample/page.tsx',
    script: 'check:sample-surface',
    guard: 'dev/check-sample-surface.mjs',
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

export function readNextConfig(projectRoot) {
  for (const configFile of nextConfigFiles) {
    const configPath = resolve(projectRoot, configFile);
    if (existsSync(configPath)) {
      return {
        file: configFile,
        source: readFileSync(configPath, 'utf8'),
      };
    }
  }

  return null;
}

export function parsePageExtensions(configSource) {
  const pageExtensionsMatch = configSource.match(/pageExtensions\s*:\s*\[([\s\S]*?)\]/m);
  if (!pageExtensionsMatch) {
    return null;
  }

  return Array.from(
    pageExtensionsMatch[1].matchAll(/['"]([A-Za-z0-9.]+)['"]/g),
    ([, extension]) => extension,
  );
}

export function readPageExtensions(projectRoot) {
  const nextConfig = readNextConfig(projectRoot);
  if (!nextConfig) {
    return {
      extensions: defaultPageExtensions,
      error: null,
    };
  }

  const configuredExtensions = parsePageExtensions(nextConfig.source);
  if (!configuredExtensions) {
    return {
      extensions: defaultPageExtensions,
      error: null,
    };
  }

  if (configuredExtensions.length === 0) {
    return {
      extensions: [],
      error: `- ${nextConfig.file} pageExtensions must list at least one extension`,
    };
  }

  return {
    extensions: configuredExtensions,
    error: null,
  };
}

export function normalizeRoutePath(filePath) {
  return filePath.replaceAll('\\', '/');
}

export function routePath(projectRoot, filePath) {
  return normalizeRoutePath(relative(projectRoot, filePath));
}

export function pageFileNames(pageExtensions) {
  return new Set(pageExtensions.map((extension) => `page.${extension}`));
}

export function isRoutableAppDirectory(entry) {
  return !entry.startsWith('_') && !entry.startsWith('@');
}

export function isRoutePage(entry, supportedPageFileNames) {
  return supportedPageFileNames.has(entry);
}

export function routeSurfaceUsesSupportedPageFile(page, supportedPageFileNames) {
  return supportedPageFileNames.has(basename(page));
}
