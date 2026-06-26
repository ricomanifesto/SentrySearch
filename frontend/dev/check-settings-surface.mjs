#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const settingsPage = readFileSync(
  resolve(process.cwd(), 'src/app/settings/page.tsx'),
  'utf8',
);
const packageJson = readFileSync(resolve(process.cwd(), 'package.json'), 'utf8');

const expectations = [
  {
    name: 'keeps settings behind the auth boundary',
    pattern: /<AuthGuard>/,
  },
  {
    name: 'reads the authenticated user from the auth context',
    pattern: /const \{ user \} = useAuth\(\)/,
  },
  {
    name: 'frames the page as workspace access controls',
    pattern: /Workspace access controls/,
  },
  {
    name: 'uses the shared surface header contract',
    pattern: /import \{ SurfaceHeader \} from ["']@\/components\/ui\/SurfaceHeader["'][\s\S]*<SurfaceHeader[\s\S]*eyebrow="Workspace boundary"/,
  },
  {
    name: 'does not lead with generic settings copy',
    absentPattern: /<h1[^>]*>Settings<\/h1>|Manage account details and report-generation preferences/,
  },
  {
    name: 'uses read-only workspace identity language',
    pattern: /Workspace identity/,
  },
  {
    name: 'uses explicit unavailable-value fallback copy',
    pattern: /Unavailable in this session/,
  },
  {
    name: 'keeps provider secrets server-side',
    pattern: /Provider keys remain server-side/,
  },
  {
    name: 'does not add client-side provider key inputs',
    absentPattern: /<input[^>]+(?:api[_-]?key|provider[_-]?key|secret|password)/i,
  },
  {
    name: 'names the generation policy surface',
    pattern: /Generation policy/,
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
    name: 'avoids nested card-style generic settings framing',
    absentPattern: /bg-white shadow rounded-lg|bg-gray-50 rounded-lg p-4/,
  },
  {
    name: 'registers the settings surface check script',
    source: packageJson,
    pattern: /"check:settings-surface": "node dev\/check-settings-surface\.mjs"/,
  },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source = settingsPage }) => (
    pattern ? !pattern.test(source) : absentPattern.test(source)
  ))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Settings surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Settings surface contract check passed (${expectations.length} expectations).`);
