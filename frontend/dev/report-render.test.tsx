import assert from 'node:assert/strict';
import test from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';

import { ReportNarrative } from '../src/components/report/ReportNarrative';
import { SourceEvidence } from '../src/components/report/SourceEvidence';
import { GenerationProgress } from '../src/components/report/GenerationProgress';
import { RouteProvenance } from '../src/components/report/RouteProvenance';
import { getQualityLabel } from '../src/lib/report-query';

test('uses the generator quality vocabulary at every score threshold', () => {
  assert.equal(getQualityLabel(null), 'Not scored');
  assert.equal(getQualityLabel(4.5), 'Excellent');
  assert.equal(getQualityLabel(4.0), 'Good');
  assert.equal(getQualityLabel(3.5), 'Acceptable');
  assert.equal(getQualityLabel(3.0), 'Needs Improvement');
  assert.equal(getQualityLabel(2.9), 'Poor');
});

test('renders report markdown as semantic prose, tables, code, and guarded links', () => {
  const markdown = [
    '## Findings',
    '',
    'Evidence is tied to [MITRE ATT&CK](https://attack.mitre.org/software/S0154/).',
    '',
    '| Signal | Value |',
    '| --- | --- |',
    '| Confidence | High |',
    '',
    '```yara',
    'rule Example { condition: true }',
    '```',
    '',
    '[unsafe](javascript:alert(1))',
  ].join('\n');

  const html = renderToStaticMarkup(<ReportNarrative markdown={markdown} />);

  assert.match(html, /<h3[^>]*>Findings<\/h3>/);
  assert.match(html, /id="report-section-findings"/);
  assert.doesNotMatch(html, /<h1/);
  assert.doesNotMatch(html, /## Findings/);
  assert.match(html, /<table/);
  assert.match(html, /class="language-yara"/);
  assert.match(
    html,
    /<a href="https:\/\/attack\.mitre\.org\/software\/S0154\/" target="_blank" rel="noopener noreferrer"/,
  );
  assert.doesNotMatch(html, /href="javascript:/);
});

test('renders structured source evidence as inspectable links', () => {
  const html = renderToStaticMarkup(
    <SourceEvidence
      sources={[
        {
          title: 'MITRE ATT&CK: Cobalt Strike',
          url: 'https://attack.mitre.org/software/S0154/',
          domain: 'attack.mitre.org',
          access_date: '2026-08-13',
          relevance_score: '0.96',
          content_type: 'Knowledge base',
          key_findings: 'Maps observed behavior to ATT&CK techniques.',
        },
      ]}
    />,
  );

  assert.match(html, /MITRE ATT&amp;CK: Cobalt Strike/);
  assert.match(html, /attack\.mitre\.org/);
  assert.match(html, /Accessed 2026-08-13/);
  assert.match(html, /Relevance 0\.96/);
  assert.match(
    html,
    /href="https:\/\/attack\.mitre\.org\/software\/S0154\/" target="_blank" rel="noopener noreferrer"/,
  );
});

test('links explicit claim attribution to source identity without duplicating the ledger', () => {
  const narrative = renderToStaticMarkup(
    <ReportNarrative
      markdown="## Detection\n\nUnexpected service creation"
      claimAttributions={[
        {
          claim_class: 'detection_indicator',
          claim: 'Unexpected service creation',
          source_ids: ['S1'],
        },
      ]}
    />,
  );
  const sources = renderToStaticMarkup(
    <SourceEvidence
      attributionStatus="attributed"
      attributionVersion="3"
      sources={[
        {
          source_id: 'S1',
          title: 'Example analysis',
          url: 'https://example.com/report',
          domain: 'example.com',
          access_date: '2026-08-14',
          relevance_score: 'High',
          content_type: 'Analysis',
          key_findings: 'Observed service creation.',
        },
      ]}
    />,
  );

  assert.match(narrative, /href="#source-S1"/);
  assert.match(sources, /id="source-S1"/);
  assert.match(sources, /attribution schema 3/);
  assert.equal((sources.match(/Example analysis/g) ?? []).length, 1);
});

test('places forensic-artifact citations outside inline code', () => {
  const narrative = renderToStaticMarkup(
    <ReportNarrative
      markdown="## Forensic artifacts\n\nObserved `payload.dll` in the injected process."
      claimAttributions={[
        {
          claim_class: 'forensic_artifact',
          claim: 'payload.dll',
          source_ids: ['S1'],
        },
      ]}
    />,
  );

  assert.match(narrative, /<code[^>]*>payload\.dll<\/code> <a href="#source-S1"/);
  assert.doesNotMatch(narrative, /<code[^>]*>[^<]*S1/);
});

test('labels canonical sample evidence as a captured snapshot', () => {
  const html = renderToStaticMarkup(
    <SourceEvidence
      dateLabel="Captured"
      sources={[
        {
          title: 'MITRE ATT&CK: Cobalt Strike',
          url: 'https://attack.mitre.org/software/S0154/',
          domain: 'attack.mitre.org',
          access_date: '2026-08-13',
          relevance_score: '0.96',
          content_type: 'Knowledge base',
          key_findings: 'Maps observed behavior to ATT&CK techniques.',
        },
      ]}
    />,
  );

  assert.match(html, /Captured 2026-08-13/);
  assert.doesNotMatch(html, /Accessed 2026-08-13/);
});

test('gives background generation a stage and elapsed-time shape', () => {
  const html = renderToStaticMarkup(
    <GenerationProgress
      toolName="Cobalt Strike"
      stage="validating"
      elapsedSeconds={125}
    />,
  );

  assert.match(html, /Validating report sections/);
  assert.match(html, /2m 05s elapsed/);
  assert.match(html, /Researching sources/);
  assert.match(html, /Saving review record/);
  assert.match(html, /first run can take longer/i);
});

test('keeps healthy default model routing silent', () => {
  const html = renderToStaticMarkup(
    <RouteProvenance
      synthesisRoute={{
        requested_models: ['google/gemma-4-26b-a4b-it:free'],
        requested_providers: ['google-ai-studio'],
        selected_models: ['google/gemma-4-26b-a4b-it:free'],
        actual_models: ['google/gemma-4-26b-a4b-it:free'],
        providers: ['Google AI Studio'],
        used_fallback: false,
        request_count: 4,
      }}
    />,
  );

  assert.equal(html, '');
});

test('discloses the actual route when report generation uses fallback', () => {
  const html = renderToStaticMarkup(
    <RouteProvenance
      synthesisRoute={{
        requested_models: ['google/gemma-4-26b-a4b-it:free'],
        requested_providers: ['google-ai-studio'],
        selected_models: ['google/gemma-4-26b-a4b-it'],
        actual_models: ['google/gemma-4-26b-a4b-it'],
        providers: ['Google AI Studio'],
        used_fallback: true,
        request_count: 4,
      }}
    />,
  );

  assert.match(html, /Routing provenance/);
  assert.match(html, /application-owned fallback route/);
  assert.match(html, /google\/gemma-4-26b-a4b-it:free/);
  assert.match(html, /google-ai-studio/);
  assert.match(html, /google\/gemma-4-26b-a4b-it/);
  assert.match(html, /Google AI Studio/);
  assert.match(html, /Report authoring/);
});
