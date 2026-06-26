#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const adminPage = readFileSync(
  resolve(process.cwd(), 'src/app/admin/page.tsx'),
  'utf8',
);
const packageJson = readFileSync(resolve(process.cwd(), 'package.json'), 'utf8');

const expectations = [
  {
    name: 'keeps admin behind the auth boundary',
    pattern: /<AuthGuard>/,
  },
  {
    name: 'frames the route as admin readiness',
    pattern: /Admin readiness center/,
  },
  {
    name: 'uses control-plane language',
    pattern: /Control plane review/,
  },
  {
    name: 'does not keep generic coming-soon placeholder copy',
    absentPattern: /Admin Dashboard|Administrative features coming soon|available in a future update/,
  },
  {
    name: 'names workspace access review',
    pattern: /Workspace access review/,
  },
  {
    name: 'names deployment posture review',
    pattern: /Deployment posture/,
  },
  {
    name: 'names report governance review',
    pattern: /Report governance/,
  },
  {
    name: 'states that actions are intentionally unavailable',
    pattern: /Read-only until admin APIs are wired/,
  },
  {
    name: 'does not add client-side admin input forms',
    absentPattern: /<(form|input|textarea|select)\b/i,
  },
  {
    name: 'does not add destructive admin controls',
    absentPattern: /delete|remove user|disable account|rotate key|revoke/i,
  },
  {
    name: 'guards the route against horizontal mobile overflow',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps layout containers shrink-safe',
    pattern: /min-w-0/,
  },
  {
    name: 'registers the admin surface check script',
    source: packageJson,
    pattern: /"check:admin-surface": "node dev\/check-admin-surface\.mjs"/,
  },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source = adminPage }) => (
    pattern ? !pattern.test(source) : absentPattern.test(source)
  ))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Admin surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Admin surface contract check passed (${expectations.length} expectations).`);
