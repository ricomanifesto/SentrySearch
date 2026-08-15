import Link from 'next/link';
import { ArrowLeftIcon, ArrowRightIcon } from '@heroicons/react/24/outline';

import { ReportNarrative } from '@/components/report/ReportNarrative';
import { SourceEvidence } from '@/components/report/SourceEvidence';
import { formatTaxonomyLabel, getQualityLabel } from '@/lib/report-query';
import { SAMPLE_REPORT } from '@/lib/sample-report';

const sampleSignals = [
  { label: 'Content quality', value: `${SAMPLE_REPORT.quality_score?.toFixed(2)} / 5.00`, detail: `${getQualityLabel(SAMPLE_REPORT.quality_score)} · readiness tracked separately` },
  { label: 'Category', value: formatTaxonomyLabel(SAMPLE_REPORT.category), detail: 'Canonical report category' },
  { label: 'Threat family', value: formatTaxonomyLabel(SAMPLE_REPORT.threat_type), detail: 'Canonical report classification' },
  { label: 'Sources', value: `${SAMPLE_REPORT.web_sources.length} cited`, detail: 'Open and inspect each source' },
];

export default function SampleReport() {
  return (
    <main data-surface="sample-report" className="overflow-x-hidden bg-[var(--surface-0)]">
      <div className="border-b border-zinc-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-3 px-6 py-4 sm:flex-row sm:items-center lg:px-8">
          <p className="text-base text-zinc-600">
            <span className="font-medium text-zinc-950">Abridged sample record.</span> It uses
            the same report renderer as the analyst workspace, with no account needed.
          </p>
          <Link
            href="/generate"
            className="group inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-4 text-base font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2"
          >
            Generate a report
            <ArrowRightIcon className="h-4 w-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
          </Link>
        </div>
      </div>

      <article className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
        <Link href="/" className="inline-flex items-center gap-1.5 text-base text-zinc-500 transition-colors hover:text-zinc-800">
          <ArrowLeftIcon className="h-4 w-4" aria-hidden="true" />
          Back to home
        </Link>

        <header className="fade-up mt-8 max-w-3xl">
          <p className="text-sm font-medium text-blue-700">Threat intelligence report</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <h1 className="font-mono text-3xl font-semibold tracking-tight text-zinc-950">{SAMPLE_REPORT.tool_name}</h1>
            <span className="rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">
              {getQualityLabel(SAMPLE_REPORT.quality_score)}
            </span>
          </div>
          <p className="mt-4 max-w-2xl text-lg leading-8 text-zinc-600">
            A curated, source-backed profile showing how the production renderer presents
            narrative, code, metadata, and citation evidence for review.
          </p>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-500">
            This sample is intentionally shorter than a generated report and omits the full
            research methodology, raw extraction record, and evaluator appendix.
          </p>
        </header>

        <dl className="fade-up fade-up-1 mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-4">
          {sampleSignals.map((signal) => (
            <div key={signal.label} className="bg-white px-5 py-4">
              <dt className="text-sm text-zinc-500">{signal.label}</dt>
              <dd className="mt-1 text-lg font-semibold text-zinc-950">{signal.value}</dd>
              <dd className="mt-0.5 text-sm text-zinc-500">{signal.detail}</dd>
            </div>
          ))}
        </dl>

        <div className="fade-up fade-up-2 mt-10 grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
          <section className="order-last min-w-0 rounded-xl border border-zinc-200 bg-white p-6 sm:p-8 lg:order-first">
            <p className="text-base font-semibold text-zinc-950">Intelligence narrative</p>
            <ReportNarrative
              markdown={SAMPLE_REPORT.markdown_content ?? ''}
              claimAttributions={SAMPLE_REPORT.claim_attributions}
            />
          </section>
          <aside className="order-first rounded-xl border border-zinc-200 bg-white p-5 lg:order-last lg:sticky lg:top-24">
            <SourceEvidence
              sources={SAMPLE_REPORT.web_sources}
              dateLabel="Captured"
              heading="Sources"
              attributionStatus={SAMPLE_REPORT.claim_attribution_status}
              attributionVersion={SAMPLE_REPORT.claim_attribution_version}
            />
          </aside>
        </div>

        <div className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-950 px-6 py-12 text-center sm:px-12">
          <h2 className="text-2xl font-semibold tracking-tight text-white">Run this on a target of your own</h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-zinc-300">
            Open the workspace to generate source-backed reports and keep the evidence beside every review record.
          </p>
          <div className="mt-8 flex justify-center">
            <Link href="/generate" className="group inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-white px-6 text-base font-medium text-zinc-950 transition-colors hover:bg-zinc-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950">
              Open workspace
              <ArrowRightIcon className="h-4 w-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </article>
    </main>
  );
}
