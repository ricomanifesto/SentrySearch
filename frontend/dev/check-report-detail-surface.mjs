import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const detailPath = resolve(here, '../src/app/reports/[id]/page.tsx');
const source = await readFile(detailPath, 'utf8');
const routeSource = await readFile(
  resolve(here, '../src/components/report/RouteProvenance.tsx'),
  'utf8',
);
const reviewStatusSource = await readFile(
  resolve(here, '../src/components/report/ReviewStatusBanner.tsx'),
  'utf8',
);
const reportStatusSource = await readFile(
  resolve(here, '../src/lib/report-status.ts'),
  'utf8',
);
const dispositionSource = await readFile(
  resolve(here, '../src/components/report/AnalystDispositionPanel.tsx'),
  'utf8',
);
const attentionSource = await readFile(resolve(here, '../src/lib/review-attention.ts'), 'utf8');

const expectations = [
  { name: 'keeps report detail behind the auth boundary', pattern: /<AuthGuard>\s*<ReportDetailContent \/>/ },
  { name: 'keeps report fetching inside the guarded detail component', pattern: /api\.getReport\(reportId, true\)/ },
  { name: 'anchors the surface as an intelligence record', pattern: /Intelligence record/ },
  { name: 'uses product-specific narrative framing', pattern: /Intelligence narrative/ },
  { name: 'renders the saved narrative through the shared markdown component', pattern: /<ReportNarrative[\s\S]*markdown=\{contentParts\.narrative\}/ },
  { name: 'does not render the saved markdown as a raw preformatted block', absentPattern: /<pre[^>]*>\s*\{report\.markdown_content\}/ },
  { name: 'declares the report detail surface contract', pattern: /data-surface="report-detail-record"/ },
  { name: 'declares the local report detail fixture id', pattern: /const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture'/ },
  { name: 'exercises research fallback disclosure in the local fixture', pattern: /const localReportDetailFixture[\s\S]*research_route:[\s\S]*used_fallback: true/ },
  { name: 'exercises authoring fallback disclosure in the local fixture', pattern: /const localReportDetailFixture[\s\S]*synthesis_route:[\s\S]*used_fallback: true/ },
  { name: 'exercises evaluation fallback disclosure in the local fixture', pattern: /const localReportDetailFixture[\s\S]*evaluation_route:[\s\S]*used_fallback: true/ },
  { name: 'guards report detail fixtures to development only', pattern: /const fixtureReport = process\.env\.NODE_ENV === 'development'/ },
  { name: 'exercises named review conflicts and append-only judgment history in a local fixture', pattern: /LOCAL_REVIEW_ATTENTION_FIXTURE_ID[\s\S]*const localReviewAttentionFixture[\s\S]*review_status: 'needs_attention'[\s\S]*analyst_disposition: 'needs_revision'[\s\S]*local-disposition-accepted[\s\S]*local-disposition-needs-revision[\s\S]*inconsistencies:/ },
  { name: 'exercises a failed run with its last stage in a local fixture', pattern: /LOCAL_FAILED_GENERATION_FIXTURE_ID[\s\S]*const localFailedGenerationFixture[\s\S]*generation_failure_stage: 'validating'/ },
  { name: 'keeps an adversarial evidence fixture for the blocked reader experience', pattern: /LOCAL_EVIDENCE_SAFETY_FIXTURE_ID[\s\S]*const localEvidenceSafetyFixture[\s\S]*eligible_for_acceptance: false[\s\S]*evidence_admissibility_status: 'blocked'[\s\S]*198\.51\.100\.87[\s\S]*source\.training-scenario/ },
  { name: 'keeps earlier acceptance as history while disabling unsafe handoff', pattern: /const localEvidenceSafetyFixture[\s\S]*eligible_for_handoff: false[\s\S]*local-prior-accepted-disposition[\s\S]*is_current: false/ },
  { name: 'exercises exact coverage blockers on a failed-generation fixture', pattern: /LOCAL_EVIDENCE_COVERAGE_FIXTURE_ID[\s\S]*const localEvidenceCoverageFixture[\s\S]*generation_error_code: 'evidence_incomplete'[\s\S]*riskFactors\[0\] lacks direct source identity/ },
  { name: 'disables report fetching when fixture data is present', pattern: /enabled: !!reportId && !fixtureReport/ },
  { name: 'prevents fixture delete actions from mutating the backend', pattern: /if \(isFixtureRecord\) return;/ },
  { name: 'declares the local report detail fixture contract', pattern: /data-contract="Report\.LocalVisualFixture\.v1"/ },
  { name: 'keeps source transparency visible', pattern: /Source transparency/ },
  { name: 'grounds source transparency in structured source evidence', pattern: /report\.web_sources\.length > 0/ },
  { name: 'renders structured source evidence beside the narrative', pattern: /<SourceEvidence[\s\S]*sources=\{report\.web_sources\}/ },
  { name: 'renders the application-owned evidence-admissibility record', pattern: /evidenceAdmissibility=\{report\.evidence_admissibility\}/ },
  { name: 'links explicit high-risk claims to the canonical source rail', pattern: /claimAttributions=\{report\.claim_attributions\}[\s\S]*attributionStatus=\{report\.claim_attribution_status\}/ },
  { name: 'frames raw technical data as structured extraction data', pattern: /Structured extraction data/ },
  { name: 'contains long structured data output', pattern: /JSON\.stringify\(report\.threat_data, null, 2\)/ },
  { name: 'uses a canonical source review checklist collection', pattern: /const sourceReviewChecklist/ },
  { name: 'renders source review guidance from the canonical checklist', pattern: /sourceReviewChecklist\.map/ },
  { name: 'declares the source review checklist contract', pattern: /data-contract="Report\.SourceReviewChecklist\.v1"/ },
  { name: 'uses a canonical record summary signals collection', pattern: /const recordSummarySignals/ },
  { name: 'renders report summary signals from the canonical collection', pattern: /recordSummarySignals\.map\(\(signal\)[\s\S]*signal\.label[\s\S]*signal\.value[\s\S]*signal\.detail/ },
  { name: 'declares the report record summary signals contract', pattern: /data-contract="Report\.RecordSummarySignals\.v1"/ },
  { name: 'puts operational readiness before quality and route detail', pattern: /<ReviewStatusBanner[\s\S]*data-contract="Report\.RecordSummarySignals\.v1"[\s\S]*<RouteProvenance/ },
  { name: 'passes split and legacy routes to the shared disclosure', pattern: /<RouteProvenance[\s\S]*generationRoute=\{report\.generation_route\}[\s\S]*researchRoute=\{report\.research_route\}[\s\S]*synthesisRoute=\{report\.synthesis_route\}[\s\S]*evaluationRoute=\{report\.evaluation_route\}/ },
  { name: 'declares the split route provenance contract', source: routeSource, pattern: /data-contract="Report\.RouteProvenance\.v2"/ },
  { name: 'keeps legacy generation aggregates honestly labeled', source: routeSource, pattern: /All generation calls \(legacy aggregate\)/ },
  { name: 'discloses only application-owned fallback routes', source: routeSource, pattern: /researchRoute\?\.used_fallback[\s\S]*synthesisRoute\?\.used_fallback[\s\S]*evaluationRoute\?\.used_fallback[\s\S]*if \(divergentRoutes\.length === 0\)[\s\S]*return null/ },
  { name: 'names the requested selected actual and provider route values', source: routeSource, pattern: /Requested[\s\S]*selected[\s\S]*resolved as[\s\S]*via/ },
  { name: 'frames the side rail as review readiness', pattern: /Review readiness/ },
  { name: 'uses the shared quality vocabulary for null scores', pattern: /const qualityLabel = getQualityLabel\(qualityScore\)/ },
  { name: 'renders unavailable confidence without fabricating zero', pattern: /qualityScore == null \? qualityLabel/ },
  { name: 'does not override the shared null quality label', absentPattern: /Evaluator unavailable/ },
  { name: 'polls while generation or evaluation work is active', pattern: /status === 'generating'[\s\S]*evaluation_status === 'pending'[\s\S]*\? 4000/ },
  { name: 'declares the generation progress component', pattern: /<GenerationProgress/ },
  { name: 'renders backend-owned generation stages', pattern: /generation_stage/ },
  { name: 'shows elapsed generation time', pattern: /elapsedSeconds/ },
  { name: 'declares the generation failed contract', pattern: /data-contract="Report\.GenerationFailed\.v1"/ },
  { name: 'offers a target-preserving retry path from a failed generation', pattern: /generate\?target=\$\{encodeURIComponent\(report\.tool_name\)\}[\s\S]*failurePresentation\.retryLabel/ },
  { name: 'derives failure copy from the persisted typed cause', pattern: /getGenerationFailurePresentation\([\s\S]*report\.generation_error_code[\s\S]*report\.generation_retryable/ },
  { name: 'renders the named evidence audit when safety or coverage gates fail', pattern: /\['evidence_inadmissible', 'evidence_incomplete'\][\s\S]*heading="Evidence gate audit"[\s\S]*evidenceAdmissibility=\{report\.evidence_admissibility\}/ },
  { name: 'does not exonerate every target without evidence', absentPattern: /Your target was not the cause; the failed record/ },
  { name: 'uses a grammatical sentence when no generation stage was recorded', pattern: /This run stopped before a generation stage was recorded/ },
  { name: 'offers evaluator-only recovery for a saved unscored narrative', pattern: /api\.retryReportEvaluation[\s\S]*<ReviewStatusBanner/ },
  { name: 'names the preserved narrative in evaluation recovery copy', source: reportStatusSource, pattern: /narrative is preserved/ },
  { name: 'announces evaluation progress politely', source: reviewStatusSource, pattern: /role=\{active \? 'status'[\s\S]*aria-live=\{active \? 'polite'/ },
  { name: 'puts source evidence before the narrative on narrow screens', pattern: /id="intelligence-narrative" className="order-last[\s\S]*id="source-evidence" className="order-first/ },
  { name: 'separates evaluation appendix from the operational narrative', pattern: /splitReportContent[\s\S]*Evaluation details/ },
  { name: 'promotes specific review conflicts into the status banner', pattern: /getReviewAttentionSummary[\s\S]*attention=\{attentionSummary\}/ },
  { name: 'lets only currently eligible analyst acceptance own operational readiness', pattern: /analystDisposition=\{report\.analyst_disposition\}[\s\S]*acceptanceEligible=\{report\.eligible_for_acceptance\}/ },
  { name: 'states that unresolved conflicts block operational reuse', source: attentionSource, pattern: /Operational reuse is blocked by[\s\S]*until an analyst records a disposition/ },
  { name: 'renders append-only analyst judgment controls', pattern: /<AnalystDispositionPanel/ },
  { name: 'prevents accepting a record before evidence admissibility passes', source: dispositionSource, pattern: /acceptanceBlocked = !report\.eligible_for_acceptance[\s\S]*Accept for reuse is unavailable/ },
  { name: 'declares the analyst disposition contract', source: dispositionSource, pattern: /data-contract="Report\.AnalystDisposition\.v1"/ },
  { name: 'names append-only judgment history', source: dispositionSource, pattern: /Each judgment is appended to the audit history/ },
  { name: 'allows re-evaluation without erasing prior judgment history', source: dispositionSource, pattern: /Re-run evaluation[\s\S]*Judgment history/ },
  { name: 'gives long reports a reader-visible outline', pattern: /Report outline · \{sectionLinks\.length\} sections/ },
  { name: 'shows classification provenance instead of collapsing unknowns', pattern: /Stored structured classification[\s\S]*Recovered from the saved structured extraction[\s\S]*does not map to the canonical taxonomy[\s\S]*Legacy record/ },
  { name: 'keeps accessible report loading semantics', pattern: /role="status"[\s\S]*aria-label="Loading report record"/ },
  { name: 'keeps accessible report error semantics', pattern: /role="alert"/ },
  { name: 'uses non-leaky report detail error copy', pattern: /This saved record could not be opened/ },
  { name: 'does not render raw loading errors', absentPattern: /error\.message|error\?\.message|String\(error\)/ },
  { name: 'keeps mobile overflow guarded', pattern: /overflow-x-hidden/ },
  { name: 'removes generic not-found heading', absentPattern: /Report Not Found/ },
  { name: 'removes generic report detail heading', absentPattern: />Report Details</ },
  { name: 'does not keep one-off report detail shell colors', absentPattern: /#f7f7f3|#6f755f|#d8d9ce|bg-slate-50/ },
  { name: 'uses product-specific destructive action copy', pattern: /Delete record/ },
  { name: 'uses an accessible in-product delete confirmation', pattern: /<Dialog[\s\S]*<DialogTitle[\s\S]*Delete this report\?[\s\S]*Delete permanently/ },
  { name: 'does not rely on a blocking browser confirmation', absentPattern: /\bconfirm\(/ },
  { name: 'keeps delete failures distinct from successful removal', pattern: /The report could not be deleted\. The saved record is still available/ },
  { name: 'uses product-specific download action copy', pattern: /Download markdown/ },
  { name: 'disables handoff unless the backend marks the current vintage eligible', pattern: /if \(!report\?\.markdown_content \|\| !report\.eligible_for_handoff\) return;[\s\S]*disabled=\{!report\.markdown_content \|\| !report\.eligible_for_handoff\}/ },
  { name: 'explains why handoff remains disabled', pattern: /Handoff stays disabled until the current evidence-safe evaluation is accepted/ },
  { name: 'does not use fonts below the legible minimum', absentPattern: /text-xs|text-\[11px\]/ },
  { name: 'does not use gradient backgrounds', absentPattern: /bg-gradient/ },
];

const failures = expectations
  .filter(({ pattern, absentPattern, source: expectationSource = source }) => (
    pattern ? !pattern.test(expectationSource) : absentPattern.test(expectationSource)
  ))
  .map(({ name }) => `- ${name}`);

if (failures.length > 0) {
  console.error(`Report detail surface contract check failed:\n${failures.join('\n')}`);
  process.exit(1);
}

console.log(`Report detail surface contract check passed (${expectations.length} expectations).`);
