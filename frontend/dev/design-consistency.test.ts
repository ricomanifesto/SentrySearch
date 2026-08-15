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
const dashboard = source('../src/app/dashboard/page.tsx');
const reports = source('../src/app/reports/page.tsx');
const reportDetail = source('../src/app/reports/[id]/page.tsx');
const generate = source('../src/app/generate/page.tsx');
const analytics = source('../src/app/analytics/page.tsx');
const exportPage = source('../src/app/export/page.tsx');
const dashboardSignals = source('../src/components/DashboardBriefingSignals.tsx');
const activityFeed = source('../src/components/ActivityFeed.tsx');
const reviewStatus = source('../src/components/report/ReviewStatusBanner.tsx');
const routeProvenance = source('../src/components/report/RouteProvenance.tsx');
const analystDisposition = source('../src/components/report/AnalystDispositionPanel.tsx');
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

test('uses open workspace composition instead of bordered cards inside bordered cards', () => {
  assert.match(dashboardSignals, /border-y border-zinc-200 py-6/);
  assert.doesNotMatch(dashboardSignals, /gap-px overflow-hidden rounded-xl/);
  assert.match(dashboard, /min-w-0 border-t border-zinc-200 pt-6/);
  assert.doesNotMatch(dashboard, /font-mono/);

  assert.match(activityFeed, /divide-y divide-zinc-200/);
  assert.doesNotMatch(activityFeed, /items-start gap-3 rounded-lg border border-zinc-100/);

  assert.match(reports, /Reports\.ReviewQueueControls\.v1[\s\S]*border-y border-zinc-200 py-5/);
  assert.match(reports, /Reports\.FailedRunLane\.v1[\s\S]*border-l-4 border-red-500 pl-5/);
  assert.doesNotMatch(reports, /gap-px overflow-hidden rounded-lg border border-zinc-200/);

  assert.match(generate, /<form[\s\S]*border-t border-zinc-200 pt-6/);
  assert.match(generate, /Generate\.TargetSeedLibrary\.v1[\s\S]*border-t border-zinc-200 pt-6/);

  assert.match(analytics, /Analytics\.MetricSignalStrip\.v1[\s\S]*border-y border-zinc-200 py-6/);
  assert.doesNotMatch(analytics, /gap-px overflow-hidden rounded/);
  assert.doesNotMatch(analytics, /font-mono/);

  assert.match(exportPage, /Package format[\s\S]*divide-y divide-zinc-200/);
  assert.match(exportPage, /Export\.PackageManifest\.v1[\s\S]*border-t border-zinc-200 pt-6/);
});

test('keeps report status and judgment hierarchy strong without nesting generic panels', () => {
  assert.match(reviewStatus, /border-l-4/);
  assert.doesNotMatch(reviewStatus, /rounded-xl border px-5 py-4/);
  assert.match(routeProvenance, /border-l-4 border-amber-500 pl-5/);
  assert.match(analystDisposition, /border-t border-zinc-200 pt-6/);
  assert.doesNotMatch(analystDisposition, /rounded-xl border border-zinc-200 bg-white p-5/);
  assert.match(reportDetail, /Report\.RecordSummarySignals\.v1[\s\S]*border-y border-zinc-200 py-6/);
  assert.doesNotMatch(reportDetail, /gap-px overflow-hidden rounded-xl border border-zinc-200/);
});
