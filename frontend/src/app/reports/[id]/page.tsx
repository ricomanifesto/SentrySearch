/**
 * Individual Report Detail Page
 *
 * Displays a single threat intelligence report with full content, metadata,
 * and export options.
 */

'use client';

import React from 'react';
import Link from 'next/link';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeftIcon, ArrowDownTrayIcon, TrashIcon } from '@heroicons/react/24/outline';

import { api, type ReportDetail } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, downloadAsFile } from '@/lib/utils';
import { SAMPLE_REPORT } from '@/lib/sample-report';
import { AuthGuard } from '@/components/AuthGuard';
import { ReportNarrative } from '@/components/report/ReportNarrative';
import { SourceEvidence } from '@/components/report/SourceEvidence';
import { GenerationProgress } from '@/components/report/GenerationProgress';

const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture';

const localReportDetailFixture: ReportDetail = {
  ...SAMPLE_REPORT,
  id: LOCAL_REPORT_DETAIL_FIXTURE_ID,
};

const secondaryButtonClass =
  'inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 disabled:pointer-events-none disabled:opacity-50';

export default function ReportDetailPage() {
  const params = useParams();
  const reportId = params?.id as string;
  const isLocalVisualFixture =
    process.env.NODE_ENV === 'development' && reportId === LOCAL_REPORT_DETAIL_FIXTURE_ID;

  return isLocalVisualFixture ? (
    <ReportDetailContent fixtureReport={localReportDetailFixture} />
  ) : (
    <AuthGuard>
      <ReportDetailContent />
    </AuthGuard>
  );
}

function ReportDetailContent({ fixtureReport }: { fixtureReport?: ReportDetail }) {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const reportId = params?.id as string;
  const isFixtureRecord = Boolean(fixtureReport);

  const { data: fetchedReport, isLoading, error } = useQuery({
    queryKey: ['report', reportId],
    queryFn: () => api.getReport(reportId, true),
    enabled: !!reportId && !fixtureReport,
    // Poll while a background generation is still running.
    refetchInterval: (query) => (query.state.data?.status === 'generating' ? 4000 : false),
  });
  const report = fixtureReport ?? fetchedReport;
  const isGenerating = report?.status === 'generating';
  const isFailed = report?.status === 'failed';
  const [elapsedSeconds, setElapsedSeconds] = React.useState(0);

  React.useEffect(() => {
    if (!isGenerating || !report?.created_at) {
      return;
    }

    const startedAt = Date.parse(report.created_at);
    const updateElapsed = () => {
      setElapsedSeconds(Number.isFinite(startedAt) ? (Date.now() - startedAt) / 1000 : 0);
    };
    const intervalId = window.setInterval(updateElapsed, 1000);
    return () => window.clearInterval(intervalId);
  }, [isGenerating, report?.created_at]);

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      router.push('/reports');
    },
  });

  const handleDownload = () => {
    if (!report?.markdown_content) return;
    const filename = `${report.tool_name.replace(/[^a-zA-Z0-9]/g, '_')}_report.md`;
    downloadAsFile(report.markdown_content, filename, 'text/markdown');
  };

  const handleDelete = () => {
    if (isFixtureRecord) return;
    if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <main className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-5xl px-6 py-12 lg:px-8" role="status" aria-label="Loading report record">
          <div className="animate-pulse space-y-5">
            <div className="h-4 w-40 rounded bg-zinc-200" />
            <div className="h-10 w-2/3 rounded bg-zinc-200" />
            <div className="grid gap-4 sm:grid-cols-4">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-20 rounded-lg bg-zinc-100" />
              ))}
            </div>
            <div className="h-80 rounded-xl bg-zinc-100" />
          </div>
        </div>
      </main>
    );
  }

  if (error || !report) {
    return (
      <main className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-2xl px-6 py-16 lg:px-8">
          <div className="rounded-xl border border-red-200 bg-red-50 px-6 py-10 text-center" role="alert">
            <h1 className="text-2xl font-semibold text-red-900">Report record unavailable</h1>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-red-700">
              This saved record could not be opened. Return to the review queue and try another report.
            </p>
            <button type="button" onClick={() => router.push('/reports')} className={`${secondaryButtonClass} mt-6`}>
              Back to saved intelligence
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (isGenerating) {
    return (
      <main data-surface="report-detail-record" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-3xl px-6 py-16 lg:px-8">
          <Link href="/reports" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-800">
            <ArrowLeftIcon className="h-4 w-4" aria-hidden="true" />
            Back to review queue
          </Link>
          <GenerationProgress
            toolName={report.tool_name}
            stage={report.generation_stage ?? 'queued'}
            elapsedSeconds={elapsedSeconds}
          />
        </div>
      </main>
    );
  }

  if (isFailed) {
    return (
      <main data-surface="report-detail-record" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-2xl px-6 py-16 lg:px-8">
          <section
            data-contract="Report.GenerationFailed.v1"
            className="rounded-xl border border-red-200 bg-red-50 px-6 py-10 text-center"
            role="alert"
          >
            <h1 className="text-2xl font-semibold text-red-900">Generation didn&apos;t finish</h1>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-red-700">
              This report couldn&apos;t be completed. Start a new run from the generate console and try the target again.
            </p>
            <button type="button" onClick={() => router.push('/generate')} className={`${secondaryButtonClass} mt-6`}>
              Start a new report
            </button>
          </section>
        </div>
      </main>
    );
  }

  const qualityScore = report.quality_score;
  const qualityLabel =
    qualityScore == null ? 'Evaluator unavailable'
      : qualityScore >= 4.0 ? 'High confidence'
      : qualityScore >= 3.0 ? 'Reviewable'
        : qualityScore >= 2.0 ? 'Needs review' : 'Low confidence';

  const recordSummarySignals = [
    {
      label: 'Confidence',
      value: qualityScore == null ? 'Not scored' : `${qualityScore.toFixed(1)} / 5.0`,
      detail: qualityLabel,
    },
    { label: 'Category', value: report.category || 'Unclassified', detail: 'Report classification' },
    { label: 'Threat type', value: report.threat_type || 'Unclassified', detail: 'Observed behavior family' },
    {
      label: 'Generated',
      value: formatRelativeTime(report.created_at),
      detail: report.processing_time_ms ? `${formatProcessingTime(report.processing_time_ms)} generation` : 'Runtime not recorded',
    },
  ];

  const sourceReviewChecklist = [
    {
      label: 'Narrative review',
      description: report.markdown_content
        ? 'Review the saved narrative against the metadata signals before reuse.'
        : 'Narrative content is absent; use structured extraction data for review context.',
      status: report.markdown_content ? 'Ready' : 'Missing narrative',
      ready: Boolean(report.markdown_content),
    },
    {
      label: 'Source transparency',
      description: report.web_sources.length > 0
        ? 'Structured source records are attached and can be opened beside the narrative.'
        : 'No structured source evidence is attached to this saved report record.',
      status: report.web_sources.length > 0 ? `${report.web_sources.length} sources` : 'No sources',
      ready: report.web_sources.length > 0,
    },
    {
      label: 'Extraction audit',
      description: report.threat_data
        ? 'Structured extraction data is available for field-level inspection.'
        : 'Structured extraction data is not saved on this report record.',
      status: report.threat_data ? 'Available' : 'Unavailable',
      ready: Boolean(report.threat_data),
    },
  ];

  return (
    <main data-surface="report-detail-record" className="overflow-x-hidden bg-[var(--surface-0)]">
      <div className="mx-auto max-w-5xl px-6 py-12 lg:px-8">
        {isFixtureRecord ? (
          <span data-contract="Report.LocalVisualFixture.v1" className="sr-only">Local report detail visual fixture</span>
        ) : null}

        <Link href="/reports" className="inline-flex items-center gap-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-800">
          <ArrowLeftIcon className="h-4 w-4" aria-hidden="true" />
          Back to review queue
        </Link>

        <div className="mt-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <p className="text-sm font-medium text-blue-700">Intelligence record</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-zinc-950">{report.tool_name}</h1>
            <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm text-zinc-500">
              <span>{formatRelativeTime(report.created_at)}</span>
              <span>{formatDate(report.created_at)}</span>
              {report.processing_time_ms ? <span>{formatProcessingTime(report.processing_time_ms)} generation</span> : null}
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button type="button" onClick={handleDownload} disabled={!report.markdown_content} className={secondaryButtonClass}>
              <ArrowDownTrayIcon className="h-4 w-4" aria-hidden="true" />
              Download markdown
            </button>
            <button
              type="button"
              onClick={handleDelete}
              disabled={isFixtureRecord || deleteMutation.isPending}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-red-200 bg-white px-4 text-sm font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-300 disabled:pointer-events-none disabled:opacity-50"
            >
              <TrashIcon className="h-4 w-4" aria-hidden="true" />
              Delete record
            </button>
          </div>
        </div>

        <dl
          data-contract="Report.RecordSummarySignals.v1"
          className="mt-8 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-2 xl:grid-cols-4"
        >
          {recordSummarySignals.map((signal) => (
            <div key={signal.label} className="min-w-0 bg-white px-4 py-4">
              <dt className="text-sm text-zinc-500">{signal.label}</dt>
              <dd className="mt-1 truncate text-base font-semibold capitalize text-zinc-950">{signal.value}</dd>
              <dd className="mt-0.5 text-sm text-zinc-500">{signal.detail}</dd>
            </div>
          ))}
        </dl>

        {report.search_tags && report.search_tags.length > 0 && (
          <div className="mt-6 flex flex-wrap gap-2">
            {report.search_tags.map((tag, index) => (
              <span key={index} className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{tag}</span>
            ))}
          </div>
        )}

        <div className="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <section className="min-w-0 rounded-xl border border-zinc-200 bg-white p-6">
            <p className="text-base font-semibold text-zinc-950">Intelligence narrative</p>
            {report.markdown_content ? (
              <ReportNarrative markdown={report.markdown_content} />
            ) : (
              <div className="mt-4 rounded-lg border border-dashed border-zinc-300 px-5 py-8 text-center">
                <p className="text-sm font-medium text-zinc-950">Narrative unavailable</p>
                <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-zinc-500">
                  This record has no saved narrative. Use the structured extraction data and tags for review context.
                </p>
              </div>
            )}
          </section>

          <aside className="min-w-0 space-y-4">
            <section className="rounded-xl border border-zinc-200 bg-white p-5">
              <SourceEvidence sources={report.web_sources} />
            </section>
            <section data-contract="Report.SourceReviewChecklist.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
              <h2 className="text-base font-semibold text-zinc-950">Review readiness</h2>
              <p className="mt-1 text-sm leading-6 text-zinc-500">
                Use these signals to review the narrative, sources, and extraction data.
              </p>
              <div className="mt-4 space-y-3">
                {sourceReviewChecklist.map((item) => (
                  <div key={item.label}>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-medium text-zinc-950">{item.label}</h3>
                      <span className={`rounded-md px-2 py-0.5 text-sm font-medium ${item.ready ? 'bg-blue-50 text-blue-700' : 'bg-amber-50 text-amber-700'}`}>
                        {item.status}
                      </span>
                    </div>
                    <p className="mt-1 text-sm leading-6 text-zinc-500">{item.description}</p>
                  </div>
                ))}
              </div>
            </section>
          </aside>
        </div>

        {report.threat_data && (
          <section className="mt-8 rounded-xl border border-zinc-200 bg-white p-6">
            <h2 className="text-base font-semibold text-zinc-950">Structured extraction data</h2>
            <pre className="mt-4 max-h-[32rem] overflow-auto rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4 font-mono text-sm leading-6 text-zinc-800">
              {JSON.stringify(report.threat_data, null, 2)}
            </pre>
          </section>
        )}
      </div>
    </main>
  );
}
