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
    name: 'uses the shared surface header contract',
    pattern: /import \{ SurfaceHeader \} from '@\/components\/ui\/SurfaceHeader';[\s\S]*<SurfaceHeader[\s\S]*eyebrow="Analyst handoff"/,
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
    name: 'uses a canonical package contents contract',
    pattern: /const packageContentOptions = \[[\s\S]*key: 'include_content'[\s\S]*label: 'Full narrative'[\s\S]*key: 'include_metadata'[\s\S]*label: 'Processing metadata'[\s\S]*key: 'include_tags'[\s\S]*label: 'Source tags'/,
  },
  {
    name: 'renders package content controls from the canonical contract',
    pattern: /packageContentOptions\.map\(\(option\)[\s\S]*checked=\{Boolean\(config\[option\.key\]\)\}[\s\S]*handleConfigChange\(option\.key, e\.target\.checked\)/,
  },
  {
    name: 'derives manifest included evidence from the canonical content contract',
    pattern: /const includedEvidenceLabels = packageContentOptions[\s\S]*\.filter\(\(option\) => Boolean\(config\[option\.key\]\)\)[\s\S]*\.map\(\(option\) => option\.label\)/,
  },
  {
    name: 'declares the package scope controls contract',
    pattern: /data-contract="Export\.PackageScopeControls\.v1"/,
  },
  {
    name: 'uses a canonical package scope controls contract',
    pattern: /type PackageScopeControl[\s\S]*const packageScopeControls: PackageScopeControl\[\] = \[[\s\S]*label: 'Review window'[\s\S]*label: 'Threat family'[\s\S]*label: 'Minimum confidence'/,
  },
  {
    name: 'renders package scope controls from the canonical contract',
    pattern: /packageScopeControls\.map\(\(control\)[\s\S]*key=\{control\.key\}[\s\S]*label=\{control\.label\}[\s\S]*options=\{control\.options\}[\s\S]*value=\{control\.value\}/,
  },
  {
    name: 'frames package scope as handoff constraints',
    pattern: /Handoff constraints[\s\S]*Constrain the package to the evidence window, threat family, and confidence floor needed for review\./,
  },
  {
    name: 'uses product-specific maximum record copy',
    pattern: /Maximum records/,
  },
  {
    name: 'does not keep generic package scope filter labels',
    absentPattern: /label="Date Range"|label="Threat Type"|label="Minimum Quality"|label="Max Reports"/,
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
    name: 'extracts export evidence records into a named component',
    pattern: /function ExportEvidenceQueueRecord\(/,
  },
  {
    name: 'uses a canonical export evidence record builder',
    pattern: /function buildExportEvidenceRecord\(/,
  },
  {
    name: 'declares each export evidence queue record contract',
    pattern: /data-contract="Export\.EvidenceQueueRecord\.v1"/,
  },
  {
    name: 'renders export evidence rows from canonical display metadata',
    pattern: /reportsData\?\.reports\.map\(\(report\) => \([\s\S]*<ExportEvidenceQueueRecord[\s\S]*record=\{buildExportEvidenceRecord\(report\)\}/,
  },
  {
    name: 'uses checkbox changes for report selection',
    pattern: /onChange=\{\(event\) => onSelectionChange\(record\.id, event\.target\.checked\)\}/,
  },
  {
    name: 'does not keep the old inline evidence queue row body',
    absentPattern: /reportsData\?\.reports\.map\(\(report\) => \{[\s\S]*const isSelected = selectedReports\.includes\(report\.id\);[\s\S]*onChange=\{\(\) => \{\}\}/,
  },
  {
    name: 'frames the sidebar summary as a package manifest',
    pattern: /Package manifest/,
  },
  {
    name: 'declares the package manifest contract',
    pattern: /data-contract="Export\.PackageManifest\.v1"/,
  },
  {
    name: 'uses a canonical package manifest row contract',
    pattern: /type PackageManifestRow[\s\S]*const packageManifestRows: PackageManifestRow\[\] = \[[\s\S]*label: 'File type'[\s\S]*label: 'Included evidence'[\s\S]*label: 'Scope boundary'/,
  },
  {
    name: 'renders package manifest rows from the canonical contract',
    pattern: /packageManifestRows\.map\(\(row\)[\s\S]*key=\{row\.label\}[\s\S]*\{row\.value\}[\s\S]*\{row\.description\}/,
  },
  {
    name: 'declares the package readiness contract',
    pattern: /data-contract="Export\.PackageReadiness\.v1"/,
  },
  {
    name: 'uses a canonical package readiness row contract',
    pattern: /type PackageReadinessRow[\s\S]*const packageReadinessRows: PackageReadinessRow\[\] = \[[\s\S]*label: 'File package'[\s\S]*label: 'Evidence queue'[\s\S]*label: 'Scope constraints'/,
  },
  {
    name: 'renders package readiness rows from the canonical contract',
    pattern: /packageReadinessRows\.map\(\(row\)[\s\S]*key=\{row\.label\}[\s\S]*\{row\.label\}[\s\S]*\{row\.status\}[\s\S]*\{row\.description\}/,
  },
  {
    name: 'does not keep generic sidebar readiness prose',
    absentPattern: /\{selectedFormat\?\.label \?\? config\.format\.toUpperCase\(\)\} package with \{packageScope\.toLowerCase\(\)\}|Filters apply before packaging/,
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
