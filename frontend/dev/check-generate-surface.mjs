import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = resolve(here, '../src/app/generate/page.tsx');
const source = await readFile(pagePath, 'utf8');

const expectations = [
  {
    name: 'keeps the report generation route state owner client-side',
    pattern: /'use client';/,
  },
  {
    name: 'keeps the report creation API boundary intact',
    pattern: /api\.createReport\(data\)/,
  },
  {
    name: 'keeps generated reports routed to the saved report view',
    pattern: /router\.push\(`\/reports\/\$\{result\.report_id\}`\)/,
  },
  {
    name: 'uses product-specific target guidance',
    pattern: /ShadowPad[\s\S]*Cobalt Strike[\s\S]*SAP NetWeaver/,
  },
  {
    name: 'anchors the surface as an analyst intake console',
    pattern: /Analyst intake console/,
  },
  {
    name: 'uses the shared surface header contract',
    pattern: /import \{ SurfaceHeader \} from '@\/components\/ui\/SurfaceHeader';[\s\S]*<SurfaceHeader[\s\S]*eyebrow="Analyst intake console"/,
  },
  {
    name: 'frames the request as analyst intake instead of a generic form',
    pattern: /Analyst intake console/,
  },
  {
    name: 'uses native radio inputs for analysis mode cards',
    pattern: /type="radio"[\s\S]*name="analysis_type"[\s\S]*setFormData\(prev => \(\{ \.\.\.prev, analysis_type: option\.value/,
  },
  {
    name: 'keeps the canonical analysis type state owner',
    pattern: /analysis_type: 'comprehensive'[\s\S]*analysis_type: option\.value as GenerateFormData\['analysis_type'\]/,
  },
  {
    name: 'uses a canonical review depth contract for mode metadata',
    pattern: /const reviewDepthOptions = \[[\s\S]*value: 'comprehensive'[\s\S]*sla: '2-5 min'[\s\S]*evidence: \[[\s\S]*source-backed narrative[\s\S]*\][\s\S]*value: 'quick'[\s\S]*sla: '30-60s'[\s\S]*value: 'custom'[\s\S]*sla: 'Variable'/,
  },
  {
    name: 'renders review depth cards from the canonical contract',
    pattern: /reviewDepthOptions\.map\(\(option\)[\s\S]*formData\.analysis_type === option\.value[\s\S]*option\.evidence\.map/,
  },
  {
    name: 'does not keep duplicate mode guidance sidebar',
    absentPattern: /Mode guidance/,
  },
  {
    name: 'uses fieldset and legend semantics for analysis mode',
    pattern: /<fieldset>\s*<legend className="text-sm font-semibold uppercase tracking-wide text-slate-500">\s*Analysis mode\s*<\/legend>/,
  },
  {
    name: 'keeps radio checked state tied to request state',
    pattern: /checked=\{formData\.analysis_type === option\.value\}/,
  },
  {
    name: 'keeps accessible error alert semantics',
    pattern: /role="alert"/,
  },
  {
    name: 'keeps the generation error state generic',
    pattern: /The report could not be generated\. Check the target and try again\./,
  },
  {
    name: 'does not render raw mutation errors',
    absentPattern: /error\?\.message|error\.message/,
  },
  {
    name: 'keeps accessible async status semantics',
    pattern: /role="status"/,
  },
  {
    name: 'keeps the primary action mobile-safe',
    pattern: /whitespace-normal/,
  },
  {
    name: 'keeps mobile layout overflow guarded',
    pattern: /overflow-x-hidden/,
  },
  {
    name: 'keeps report quality guidance visible',
    pattern: /Review quality gates/,
  },
  {
    name: 'declares the target seed library contract',
    pattern: /data-contract="Generate\.TargetSeedLibrary\.v1"/,
  },
  {
    name: 'uses a typed target seed group contract',
    pattern: /type TargetSeedGroup[\s\S]*const targetGroups: TargetSeedGroup\[\] = \[[\s\S]*label: 'Observed threats'[\s\S]*description: 'Seed requests with malware families and attack tools already seen in analyst queues\.'[\s\S]*label: 'Exposed technologies'/,
  },
  {
    name: 'renders target seed groups from the canonical contract',
    pattern: /targetGroups\.map\(\(group\)[\s\S]*key=\{group\.label\}[\s\S]*\{group\.description\}[\s\S]*group\.examples\.map/,
  },
  {
    name: 'frames target examples as a target seed library',
    pattern: /Target seed library/,
  },
  {
    name: 'declares the quality gate checklist contract',
    pattern: /data-contract="Generate\.QualityGateChecklist\.v1"/,
  },
  {
    name: 'uses a typed quality gate contract',
    pattern: /type QualityGateRow[\s\S]*const qualityGates: QualityGateRow\[\] = \[[\s\S]*label: 'Source-backed findings'[\s\S]*status: 'Required'[\s\S]*label: 'Detection and mitigation guidance'[\s\S]*label: 'Risk and confidence framing'/,
  },
  {
    name: 'renders quality gates from the canonical contract',
    pattern: /qualityGates\.map\(\(gate\)[\s\S]*key=\{gate\.label\}[\s\S]*\{gate\.status\}[\s\S]*\{gate\.description\}/,
  },
  {
    name: 'frames quality expectations as review gates',
    pattern: /Review quality gates/,
  },
  {
    name: 'does not keep generic sidebar helper headings',
    absentPattern: /Seed a target|Report quality checks/,
  },
  {
    name: 'uses a canonical submission handoff contract',
    pattern: /const submissionHandoffChecks = \[[\s\S]*label: 'Target'[\s\S]*label: 'Review depth'[\s\S]*label: 'Guidance layer'/,
  },
  {
    name: 'renders submission handoff checks from the canonical contract',
    pattern: /submissionHandoffChecks\.map\(\(check\)[\s\S]*check\.label[\s\S]*check\.description/,
  },
  {
    name: 'frames the final action as a submission handoff',
    pattern: /Submission handoff/,
  },
  {
    name: 'does not keep the split readiness block',
    absentPattern: /Intake readiness/,
  },
  {
    name: 'does not keep the generic submit footer copy',
    absentPattern: /Submit only when the request target and review posture match the analyst queue\./,
  },
  {
    name: 'does not add generic gradient decoration',
    absentPattern: /bg-gradient|from-|via-|to-/,
  },
  {
    name: 'does not retain generic mode labels',
    absentPattern: /Comprehensive Analysis|Quick Analysis|Custom Analysis/,
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
  console.error('Generate surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Generate surface contract check passed (${expectations.length} expectations).`);
