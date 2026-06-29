import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = resolve(here, '../src/app/export/page.tsx');
const source = await readFile(pagePath, 'utf8');

const expectations = [
  { name: 'keeps the export route behind the auth boundary', pattern: /<AuthGuard>/ },
  { name: 'declares the export handoff surface contract', pattern: /data-surface="export-handoff"/ },
  { name: 'frames the surface as an intelligence handoff package', pattern: /Intelligence handoff package/ },
  { name: 'runs export through the backend export contract', pattern: /api\.exportReports/ },
  { name: 'downloads the prepared package', pattern: /downloadAsFile\(data, filename, mimeType\)/ },
  { name: 'uses a canonical format options collection', pattern: /const formatOptions = \[/ },
  { name: 'renders package formats from the canonical collection', pattern: /formatOptions\.map/ },
  { name: 'uses a canonical package content options collection', pattern: /const packageContentOptions = \[/ },
  { name: 'renders package contents from the canonical collection', pattern: /packageContentOptions\.map/ },
  { name: 'declares the package scope controls contract', pattern: /data-contract="Export\.PackageScopeControls\.v1"/ },
  { name: 'uses a canonical package scope controls collection', pattern: /const packageScopeControls/ },
  { name: 'renders scope controls from the canonical collection', pattern: /packageScopeControls\.map/ },
  { name: 'declares the package manifest contract', pattern: /data-contract="Export\.PackageManifest\.v1"/ },
  { name: 'uses a canonical package manifest collection', pattern: /const packageManifestRows/ },
  { name: 'renders the manifest from the canonical collection', pattern: /packageManifestRows\.map/ },
  { name: 'declares the package readiness contract', pattern: /data-contract="Export\.PackageReadiness\.v1"/ },
  { name: 'uses a canonical package readiness collection', pattern: /const packageReadinessRows/ },
  { name: 'renders readiness from the canonical collection', pattern: /packageReadinessRows\.map/ },
  { name: 'declares the evidence queue record contract', pattern: /data-contract="Export\.EvidenceQueueRecord\.v1"/ },
  { name: 'extracts evidence queue rendering into a named component', pattern: /function ExportEvidenceQueueRecord\(/ },
  { name: 'builds evidence records through a canonical helper', pattern: /function buildExportEvidenceRecord\(/ },
  { name: 'supports selecting all visible reports', pattern: /handleSelectAll/ },
  { name: 'uses accessible export pending semantics', pattern: /role="status"[\s\S]*Preparing export package for download/ },
  { name: 'uses accessible export error semantics', pattern: /role="alert"[\s\S]*The export package could not be prepared/ },
  { name: 'uses product-specific package action copy', pattern: /Prepare package/ },
  { name: 'guards the route against horizontal mobile overflow', pattern: /overflow-x-hidden/ },
  { name: 'keeps layout containers shrink-safe', pattern: /min-w-0/ },
  { name: 'does not render raw export errors', absentPattern: /error\.message|error\?\.message/ },
  { name: 'does not use fonts below the legible minimum', absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', absentPattern: /bg-gradient/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern }) => (pattern ? !pattern.test(source) : absentPattern.test(source)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Export surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Export surface contract check passed (${expectations.length} expectations).`);
