#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const settingsPage = readFileSync(resolve(process.cwd(), 'src/app/settings/page.tsx'), 'utf8');
const packageJson = readFileSync(resolve(process.cwd(), 'package.json'), 'utf8');

const expectations = [
  { name: 'keeps settings behind the auth boundary', source: settingsPage, pattern: /<AuthGuard>/ },
  { name: 'declares the settings workspace surface contract', source: settingsPage, pattern: /data-surface="settings-workspace"/ },
  { name: 'frames the surface as workspace access', source: settingsPage, pattern: /Workspace access/ },
  { name: 'reads identity from the authenticated session', source: settingsPage, pattern: /user\?\.email/ },
  { name: 'surfaces workspace identity', source: settingsPage, pattern: /Workspace identity/ },
  { name: 'surfaces the generation policy', source: settingsPage, pattern: /Generation policy/ },
  { name: 'states that provider keys stay server-side', source: settingsPage, pattern: /Provider keys stay server-side/ },
  { name: 'does not collect provider credentials in the browser', source: settingsPage, absentPattern: /type="password"|API key/ },
  { name: 'guards against horizontal mobile overflow', source: settingsPage, pattern: /overflow-x-hidden/ },
  { name: 'does not use fonts below the legible minimum', source: settingsPage, absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', source: settingsPage, absentPattern: /bg-gradient/ },
  { name: 'registers the settings surface check script', source: packageJson, pattern: /"check:settings-surface": "node dev\/check-settings-surface\.mjs"/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Settings surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Settings surface contract check passed (${expectations.length} expectations).`);
