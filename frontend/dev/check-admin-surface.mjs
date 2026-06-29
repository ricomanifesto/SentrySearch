#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const adminPage = readFileSync(resolve(process.cwd(), 'src/app/admin/page.tsx'), 'utf8');
const packageJson = readFileSync(resolve(process.cwd(), 'package.json'), 'utf8');

const expectations = [
  { name: 'keeps admin behind the auth boundary', source: adminPage, pattern: /<AuthGuard>/ },
  { name: 'declares the admin readiness surface contract', source: adminPage, pattern: /data-surface="admin-readiness"/ },
  { name: 'frames the surface as an admin readiness center', source: adminPage, pattern: /Admin readiness center/ },
  { name: 'uses a canonical readiness areas collection', source: adminPage, pattern: /const readinessAreas = \[/ },
  { name: 'renders readiness areas from the canonical collection', source: adminPage, pattern: /readinessAreas\.map/ },
  { name: 'documents the administrative surface boundary', source: adminPage, pattern: /Administrative surface status/ },
  { name: 'states the route is intentionally non-mutating', source: adminPage, pattern: /intentionally non-mutating/ },
  { name: 'reserves admin actions for the backend', source: adminPage, pattern: /No destructive workspace actions/ },
  { name: 'guards against horizontal mobile overflow', source: adminPage, pattern: /overflow-x-hidden/ },
  { name: 'does not use fonts below the legible minimum', source: adminPage, absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', source: adminPage, absentPattern: /bg-gradient/ },
  { name: 'registers the admin surface check script', source: packageJson, pattern: /"check:admin-surface": "node dev\/check-admin-surface\.mjs"/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Admin surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Admin surface contract check passed (${expectations.length} expectations).`);
