import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

const layout = source('../src/app/layout.tsx');
const css = source('../src/app/globals.css');
const landing = source('../src/app/page.tsx');
const sample = source('../src/app/sample/page.tsx');
const sourceEvidence = source('../src/components/report/SourceEvidence.tsx');
const handoffUrl = new URL('../src/components/WorkspaceHandoff.tsx', import.meta.url);
const handoff = existsSync(handoffUrl) ? source('../src/components/WorkspaceHandoff.tsx') : '';

test('loads the declared product typeface through the root layout', () => {
  assert.match(layout, /import \{ Inter \} from ['"]next\/font\/google['"]/);
  assert.match(layout, /const inter = Inter\(\{[\s\S]*variable: ['"]--font-inter['"]/);
  assert.match(layout, /className=\{`\$\{inter\.variable\} h-full`\}/);
  assert.match(css, /--font-sans:\s*var\(--font-inter\)/);
});

test('keeps secondary copy legible without competing with body text', () => {
  assert.match(css, /--text-sm:\s*0\.9375rem/);
  assert.match(css, /--text-sm--line-height:\s*1\.5rem/);
});

test('reserves monospace for machine-readable report evidence', () => {
  assert.doesNotMatch(landing, /font-mono[^>]*>\{SAMPLE_REPORT\.tool_name\}/);
  assert.doesNotMatch(landing, /font-mono[^>]*>\{step\.n\}/);
  assert.doesNotMatch(sample, /<h1 className="[^"]*font-mono/);
  assert.match(sourceEvidence, /font-mono[^>]*>\{source\.domain\}/);
});

test('uses one live workspace handoff instead of duplicated generic CTA panels', () => {
  assert.ok(existsSync(handoffUrl), 'WorkspaceHandoff component is missing');
  assert.match(handoff, /Start with evidence attached/);
  assert.match(handoff, /Open workspace/);
  assert.match(landing, /<WorkspaceHandoff/);
  assert.match(sample, /<WorkspaceHandoff/);
  assert.doesNotMatch(landing, /rounded-2xl[^\"]*bg-zinc-950/);
  assert.doesNotMatch(sample, /rounded-2xl[^\"]*bg-zinc-950/);
});

test('does not retain unused starter assets or a parallel component palette', () => {
  const retiredPaths = [
    '../public/file.svg',
    '../public/globe.svg',
    '../public/next.svg',
    '../public/vercel.svg',
    '../public/window.svg',
    '../src/components/ui/Badge.tsx',
    '../src/components/ui/Button.tsx',
    '../src/components/ui/Card.tsx',
    '../src/components/ui/Input.tsx',
    '../src/components/ui/Select.tsx',
    '../src/components/ui/SurfaceHeader.tsx',
    '../src/components/ui/Textarea.tsx',
  ];

  for (const relativePath of retiredPaths) {
    assert.equal(
      existsSync(fileURLToPath(new URL(relativePath, import.meta.url))),
      false,
      `${relativePath} should be removed`,
    );
  }
});
