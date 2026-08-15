import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const samplePath = resolve(here, '../src/app/sample/page.tsx');
const sample = await readFile(samplePath, 'utf8');
const sampleReport = await readFile(resolve(here, '../src/lib/sample-report.ts'), 'utf8');

const expectations = [
  {
    name: 'declares the sample-report surface contract',
    source: sample,
    pattern: /data-surface="sample-report"/,
  },
  {
    name: 'labels the page as a sample',
    source: sample,
    pattern: /Abridged sample record/,
  },
  {
    name: 'states that no account is required',
    source: sample,
    pattern: /no account needed/,
  },
  {
    name: 'frames the content as a threat-intelligence report',
    source: sample,
    pattern: /Threat intelligence report/,
  },
  {
    name: 'ties findings to their sources',
    source: sample,
    pattern: /Sources/,
  },
  {
    name: 'uses the production markdown renderer',
    source: sample,
    pattern: /<ReportNarrative[\s\S]*markdown=\{SAMPLE_REPORT\.markdown_content \?\? ''\}[\s\S]*claimAttributions=\{SAMPLE_REPORT\.claim_attributions\}/,
  },
  {
    name: 'renders inspectable structured source links',
    source: sample,
    pattern: /<SourceEvidence[\s\S]*sources=\{SAMPLE_REPORT\.web_sources\}[\s\S]*dateLabel="Captured"/,
  },
  {
    name: 'labels fixed source dates as historical capture dates',
    source: sample,
    pattern: /dateLabel="Captured"/,
  },
  {
    name: 'demonstrates versioned claim attribution against the source rail',
    source: sample,
    pattern: /claimAttributions=\{SAMPLE_REPORT\.claim_attributions\}[\s\S]*attributionStatus=\{SAMPLE_REPORT\.claim_attribution_status\}/,
  },
  {
    name: 'derives the threat family from the canonical sample report',
    source: sample,
    pattern: /formatTaxonomyLabel\(SAMPLE_REPORT\.threat_type\)/,
  },
  {
    name: 'separates content quality from analyst readiness',
    source: sample,
    pattern: /label: 'Content quality'/,
  },
  {
    name: 'puts source evidence first on narrow screens',
    source: sample,
    pattern: /<section className="order-last[\s\S]*<aside className="order-first/,
  },
  {
    name: 'does not hardcode a competing threat-family label',
    source: sample,
    absentPattern: /value: 'Dual-use'/,
  },
  {
    name: 'uses monospace for source and identifier detail',
    source: sample,
    pattern: /font-mono/,
  },
  {
    name: 'routes the call to action through the intent-preserving workspace boundary',
    source: sample,
    pattern: /href="\/generate"/,
  },
  {
    name: 'names the content omitted from the abridged fixture',
    source: sample,
    pattern: /omits the full[\s\S]*research methodology[\s\S]*raw extraction record[\s\S]*evaluator appendix/,
  },
  {
    name: 'does not misroute signed-in readers to account creation',
    source: sample,
    absentPattern: /href="\/auth\/signup"/,
  },
  {
    name: 'offers a path back to the public home',
    source: sample,
    pattern: /href="\/"/,
  },
  {
    name: 'does not gate the public sample behind the auth boundary',
    source: sample,
    absentPattern: /AuthGuard/,
  },
  {
    name: 'teaches the split research and authoring provenance shape',
    source: sampleReport,
    pattern: /research_route:[\s\S]*synthesis_route:[\s\S]*evaluation_route:/,
  },
  {
    name: 'does not teach the legacy aggregate route shape in the sample',
    source: sampleReport,
    absentPattern: /generation_route:/,
  },
  {
    name: 'pins every high-risk claim class in the teaching fixture',
    source: sampleReport,
    pattern: /claim_class: 'threat_activity'[\s\S]*claim_class: 'forensic_artifact'[\s\S]*claim_class: 'detection_indicator'[\s\S]*claim_class: 'mitigation_action'/,
  },
  {
    name: 'teaches current claim attribution schema 4',
    source: sampleReport,
    pattern: /claim_attribution_version: '4'[\s\S]*schemaVersion: '4'/,
  },
  {
    name: 'teaches the current deterministic evidence-admissibility contract',
    source: sampleReport,
    pattern: /evidence_admissibility_status: 'passed'[\s\S]*schema_version: '1'/,
  },
  {
    name: 'teaches explicit claim selectors instead of duplicated model prose',
    source: sampleReport,
    pattern: /claimField: 'riskFactors'[\s\S]*claimField: 'memoryArtifacts'[\s\S]*claimField: 'behavioralIndicators'[\s\S]*claimField: 'preventiveMeasures'/,
  },
  {
    name: 'uses an artifact observation for the forensic-artifact class',
    source: sampleReport,
    pattern: /A memory-resident Beacon payload inside an injected process is a forensic artifact/,
  },
  {
    name: 'does not use fonts below the legible minimum',
    source: sample,
    absentPattern: /text-xs/,
  },
  {
    name: 'does not advertise a fabricated generation-time SLA',
    source: sample,
    absentPattern: /2-5 min|30-60s/,
  },
];

const failures = expectations.filter(({ source, pattern, absentPattern }) => {
  if (pattern && !pattern.test(source)) {
    return true;
  }

  if (absentPattern && absentPattern.test(source)) {
    return true;
  }

  return false;
});

if (failures.length > 0) {
  console.error('Sample surface contract check failed:');
  for (const failure of failures) {
    console.error(`- ${failure.name}`);
  }
  process.exit(1);
}

console.log(`Sample surface contract check passed (${expectations.length} expectations).`);
