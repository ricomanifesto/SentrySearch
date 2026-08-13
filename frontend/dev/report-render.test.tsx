import assert from 'node:assert/strict';
import test from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';

import { ReportNarrative } from '../src/components/report/ReportNarrative';
import { SourceEvidence } from '../src/components/report/SourceEvidence';
import { GenerationProgress } from '../src/components/report/GenerationProgress';

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
