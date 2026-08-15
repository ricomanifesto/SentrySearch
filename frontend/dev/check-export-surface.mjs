import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = resolve(here, '../src/app/export/page.tsx');
const source = await readFile(pagePath, 'utf8');
const exportBuilder = await readFile(resolve(here, '../src/lib/report-export.ts'), 'utf8');
const exportReadiness = await readFile(resolve(here, '../src/lib/export-readiness.ts'), 'utf8');

const expectations = [
  { name: 'keeps the export route behind the auth boundary', pattern: /<AuthGuard>/ },
  { name: 'declares the export handoff surface contract', pattern: /data-surface="export-handoff"/ },
  { name: 'frames the surface as an intelligence handoff package', pattern: /Intelligence handoff package/ },
  { name: 'runs export through the report export contract', pattern: /api\.exportReports/ },
  { name: 'downloads the prepared package', pattern: /downloadAsFile\(data, filename, mimeType\)/ },
  { name: 'offers the canonical source ledger as an export layer', pattern: /label: 'Source evidence'[\s\S]*include_sources/ },
  { name: 'uses content quality vocabulary for export constraints', pattern: /Minimum content quality/ },
  { name: 'defaults handoff exports to accepted records', pattern: /analyst_dispositions: \['accepted'\]/ },
  { name: 'asks the backend for only currently eligible handoff records', pattern: /eligible_for_handoff: true/ },
  { name: 'derives package readiness from the resolved matching count', pattern: /getExportScopeState\(/ },
  { name: 'names the zero-result scope as zero records', source: exportReadiness, pattern: /packageScope: '0 records'/ },
  { name: 'states that an empty package has nothing ready', source: exportReadiness, pattern: /readinessStatus: 'Nothing ready'/ },
  { name: 'uses an unavailable action label for an empty package', source: exportReadiness, pattern: /actionLabel: 'No package to prepare'/ },
  { name: 'disables package preparation when nothing is ready', pattern: /disabled=\{exportMutation\.isPending \|\| !exportScope\.canPrepare\}/ },
  { name: 'keeps every scope constraint in the preview query', pattern: /date_range_days: config\.date_range_days[\s\S]*threat_types: config\.threat_types[\s\S]*min_quality_score: config\.min_quality_score/ },
  { name: 'keeps preview failures distinct from empty results', pattern: /The handoff scope could not be loaded[\s\S]*No package will be prepared/ },
  { name: 'makes lifecycle scope explicit in the package controls', pattern: /label: 'Lifecycle scope'/ },
  { name: 'shows review state on every selectable export record', pattern: /getReviewStatusLabel\(record\.reviewStatus\)/ },
  { name: 'shows analyst disposition on every selectable export record', pattern: /getAnalystDispositionLabel\(record\.analystDisposition\)/ },
  { name: 'exports source evidence rather than only search tags', source: exportBuilder, pattern: /include_sources[\s\S]*web_sources: report\.web_sources/ },
  { name: 'exports explicit claim attribution with its evidence ledger', source: exportBuilder, pattern: /web_sources: report\.web_sources,[\s\S]*claim_attributions: report\.claim_attributions,[\s\S]*evidence_admissibility:/ },
  { name: 'exports evaluation lifecycle and review readiness', source: exportBuilder, pattern: /evaluation_status[\s\S]*review_status/ },
  { name: 'exports split and legacy route attestation', source: exportBuilder, pattern: /generation_route[\s\S]*research_route[\s\S]*synthesis_route[\s\S]*evaluation_route/ },
  { name: 'exports current disposition and append-only history', source: exportBuilder, pattern: /analyst_disposition[\s\S]*current_disposition[\s\S]*disposition_history/ },
  { name: 'exports the backend-owned handoff decision', source: exportBuilder, pattern: /eligible_for_handoff: report\.eligible_for_handoff/ },
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
  { name: 'uses product-specific package action copy', source: exportReadiness, pattern: /actionLabel: 'Prepare package'/ },
  { name: 'guards the route against horizontal mobile overflow', pattern: /overflow-x-hidden/ },
  { name: 'keeps layout containers shrink-safe', pattern: /min-w-0/ },
  { name: 'does not render raw export errors', absentPattern: /error\.message|error\?\.message/ },
  { name: 'does not use fonts below the legible minimum', absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', absentPattern: /bg-gradient/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source: expectationSource = source }) => (pattern ? !pattern.test(expectationSource) : absentPattern.test(expectationSource)))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Export surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Export surface contract check passed (${expectations.length} expectations).`);
