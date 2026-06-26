import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = resolve(here, '../src/app/export/page.tsx');
const source = await readFile(pagePath, 'utf8');

const expectations = [
  {
    name: 'keeps the export route behind the auth boundary',
    pattern: /<AuthGuard>/,
  },
  {
    name: 'keeps the export API boundary intact',
    pattern: /api\.exportReports\(exportConfig\)/,
  },
  {
    name: 'keeps downloaded files routed through the utility helper',
    pattern: /downloadAsFile\(data, filename, mimeType\)/,
  },
  {
    name: 'frames the surface as an intelligence handoff package builder',
    pattern: /Intelligence handoff package/,
  },
  {
    name: 'does not lead with generic export reports copy',
    absentPattern: /Export Reports|Bulk export threat intelligence reports/,
  },
  {
    name: 'uses native radio inputs for export format cards',
    pattern: /type="radio"[\s\S]*name="export_format"[\s\S]*handleConfigChange\('format', format\.value\)/,
  },
  {
    name: 'uses fieldset and direct legend semantics for export format',
    pattern: /<fieldset>\s*<legend className="text-sm font-semibold uppercase tracking-wide text-slate-500">\s*Package format\s*<\/legend>/,
  },
  {
    name: 'keeps radio checked state tied to export config',
    pattern: /checked=\{config\.format === format\.value\}/,
  },
  {
    name: 'keeps accessible error alert semantics',
    pattern: /role="alert"/,
  },
  {
    name: 'keeps export failure copy safe and product-specific',
    pattern: /The export package could not be prepared\. Adjust the package settings and try again\./,
  },
  {
    name: 'does not render raw mutation errors',
    absentPattern: /exportMutation\.error\.message|error\.message|error\?\.message/,
  },
  {
    name: 'keeps accessible export progress semantics',
    pattern: /role="status"/,
  },
  {
    name: 'keeps mobile layout overflow guarded',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps package readiness visible near the action',
    pattern: /Package readiness/,
  },
  {
    name: 'frames report selection as an evidence queue',
    pattern: /Evidence queue/,
  },
  {
    name: 'shows queue scope near report selection',
    pattern: /Visible reports ready for handoff review/,
  },
  {
    name: 'frames the sidebar summary as a package manifest',
    pattern: /Package manifest/,
  },
  {
    name: 'uses confidence language for selected report scores',
    pattern: /Confidence/,
  },
  {
    name: 'does not keep demo-oriented implementation comments',
    absentPattern: /simplified for demo/i,
  },
  {
    name: 'does not add generic gradient decoration',
    absentPattern: /bg-gradient|from-|via-|to-/,
  },
];

const failures = expectations.filter(({ pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }

  if (absentPattern && absentPattern.test(source)) {
    return true;
  }

  return false;
});

if (failures.length > 0) {
  console.error('Export surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Export surface contract check passed (${expectations.length} expectations).`);
