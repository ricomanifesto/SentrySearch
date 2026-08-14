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
import { Dialog, DialogPanel, DialogTitle } from '@headlessui/react';

import { api, type ReportDetail } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, downloadAsFile } from '@/lib/utils';
import { SAMPLE_REPORT } from '@/lib/sample-report';
import { getQualityLabel } from '@/lib/report-query';
import { splitReportContent } from '@/lib/report-content';
import { AuthGuard } from '@/components/AuthGuard';
import { ReportNarrative } from '@/components/report/ReportNarrative';
import { SourceEvidence } from '@/components/report/SourceEvidence';
import { GenerationProgress } from '@/components/report/GenerationProgress';
import { RouteProvenance } from '@/components/report/RouteProvenance';
import { ReviewStatusBanner } from '@/components/report/ReviewStatusBanner';

const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture';

const localReportDetailFixture: ReportDetail = {
  ...SAMPLE_REPORT,
  id: LOCAL_REPORT_DETAIL_FIXTURE_ID,
  quality_score: null,
  evaluation_status: 'failed',
  evaluation_error_code: 'evaluator_unavailable',
  evaluation_attempts: 1,
  review_status: 'needs_evaluation',
  quality_assessment: null,
  generation_route: {
    requested_models: ['google/gemma-4-26b-a4b-it:free'],
    requested_providers: ['google-ai-studio'],
    selected_models: ['google/gemma-4-26b-a4b-it'],
    actual_models: ['google/gemma-4-26b-a4b-it'],
    providers: ['OpenAI'],
    used_fallback: true,
    request_count: 4,
  },
  evaluation_route: {
    requested_models: ['google/gemma-4-31b-it:free'],
    requested_providers: ['google-ai-studio'],
    selected_models: ['google/gemma-4-31b-it'],
    actual_models: ['google/gemma-4-31b-it'],
    providers: ['Friendli'],
    used_fallback: true,
    request_count: 12,
  },
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
    refetchInterval: (query) => (
      query.state.data?.status === 'generating'
      || query.state.data?.evaluation_status === 'pending'
        ? 4000
        : false
    ),
  });
  const report = fixtureReport ?? fetchedReport;
  const isGenerating = report?.status === 'generating';
  const isFailed = report?.status === 'failed';
  const [elapsedSeconds, setElapsedSeconds] = React.useState(0);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = React.useState(false);

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
  const evaluationMutation = useMutation({
    mutationFn: () => api.retryReportEvaluation(reportId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['report', reportId] });
      await queryClient.invalidateQueries({ queryKey: ['reports'] });
      await queryClient.invalidateQueries({ queryKey: ['analytics'] });
    },
  });

  const handleDownload = () => {
    if (!report?.markdown_content) return;
    const filename = `${report.tool_name.replace(/[^a-zA-Z0-9]/g, '_')}_report.md`;
    downloadAsFile(report.markdown_content, filename, 'text/markdown');
  };

  const handleDelete = () => {
    if (isFixtureRecord) return;
    setDeleteConfirmationOpen(true);
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
              This report couldn&apos;t be completed. Your target was not the cause; start a new run when the service is ready.
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
  const qualityLabel = getQualityLabel(qualityScore);
  const contentParts = splitReportContent(report.markdown_content || '');

  const recordSummarySignals = [
    {
      label: 'Report quality',
      value: qualityScore == null ? qualityLabel : `${qualityScore.toFixed(2)} / 5.00`,
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
      status: report.markdown_content ? 'Available' : 'Missing narrative',
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
    <>
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

        <RouteProvenance
          generationRoute={report.generation_route}
          evaluationRoute={report.evaluation_route}
        />

        <ReviewStatusBanner
          status={report.review_status}
          retryPending={evaluationMutation.isPending}
          retryDisabled={isFixtureRecord}
          retryError={evaluationMutation.isError}
          onRetry={() => evaluationMutation.mutate()}
        />

        {report.search_tags && report.search_tags.length > 0 && (
          <div className="mt-6 flex flex-wrap gap-2">
            {report.search_tags.map((tag, index) => (
              <span key={index} className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{tag}</span>
            ))}
          </div>
        )}

        <nav aria-label="Report sections" className="mt-6 flex flex-wrap gap-3 text-sm">
          <a href="#source-evidence" className="font-medium text-blue-700 hover:underline">Review sources</a>
          <a href="#intelligence-narrative" className="font-medium text-blue-700 hover:underline">Read narrative</a>
          {contentParts.appendices ? <a href="#evaluation-appendix" className="font-medium text-blue-700 hover:underline">Inspect evaluation</a> : null}
        </nav>

        <div className="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <section id="intelligence-narrative" className="order-last min-w-0 scroll-mt-6 rounded-xl border border-zinc-200 bg-white p-6 lg:order-first">
            <p className="text-base font-semibold text-zinc-950">Intelligence narrative</p>
            {report.markdown_content ? (
              <ReportNarrative markdown={contentParts.narrative} />
            ) : (
              <div className="mt-4 rounded-lg border border-dashed border-zinc-300 px-5 py-8 text-center">
                <p className="text-sm font-medium text-zinc-950">Narrative unavailable</p>
                <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-zinc-500">
                  This record has no saved narrative. Use the structured extraction data and tags for review context.
                </p>
              </div>
            )}
          </section>

          <aside id="source-evidence" className="order-first min-w-0 scroll-mt-6 space-y-4 lg:order-last">
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

        {contentParts.appendices ? (
          <details id="evaluation-appendix" className="mt-8 scroll-mt-6 rounded-xl border border-zinc-200 bg-white p-6">
            <summary className="cursor-pointer text-base font-semibold text-zinc-950 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
              Evaluation details
            </summary>
            <p className="mt-2 text-sm leading-6 text-zinc-500">
              Inspect section scores and recommendations separately from the operational narrative.
            </p>
            <ReportNarrative markdown={contentParts.appendices} />
          </details>
        ) : null}

        {report.threat_data && (
          <details className="mt-8 rounded-xl border border-zinc-200 bg-white p-6">
            <summary className="cursor-pointer text-base font-semibold text-zinc-950 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
              Structured extraction data
            </summary>
            <p className="mt-2 text-sm leading-6 text-zinc-500">Reader-safe fields used to build the saved narrative.</p>
            <pre className="mt-4 max-h-[32rem] overflow-auto rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4 font-mono text-sm leading-6 text-zinc-800">
              {JSON.stringify(report.threat_data, null, 2)}
            </pre>
          </details>
        )}
      </div>
    </main>
    <Dialog
      open={deleteConfirmationOpen}
      onClose={() => {
        if (!deleteMutation.isPending) setDeleteConfirmationOpen(false);
      }}
      className="relative z-50"
    >
      <div className="fixed inset-0 bg-zinc-950/40" aria-hidden="true" />
      <div className="fixed inset-0 flex items-center justify-center overflow-y-auto p-4">
        <DialogPanel className="w-full max-w-md rounded-xl border border-zinc-200 bg-white p-6 shadow-xl">
          <DialogTitle className="text-xl font-semibold text-zinc-950">Delete this report?</DialogTitle>
          <p className="mt-3 text-sm leading-6 text-zinc-600">
            The saved narrative, source evidence, and review history for {report.tool_name} will be permanently removed.
          </p>
          {deleteMutation.isError ? (
            <p className="mt-3 text-sm text-red-700" role="alert">
              The report could not be deleted. The saved record is still available.
            </p>
          ) : null}
          <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
            <button
              type="button"
              disabled={deleteMutation.isPending}
              onClick={() => setDeleteConfirmationOpen(false)}
              className={secondaryButtonClass}
            >
              Keep report
            </button>
            <button
              type="button"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate()}
              className="inline-flex h-10 items-center justify-center rounded-lg bg-red-700 px-4 text-sm font-medium text-white transition-colors hover:bg-red-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400 disabled:pointer-events-none disabled:opacity-50"
            >
              {deleteMutation.isPending ? 'Deleting report…' : 'Delete permanently'}
            </button>
          </div>
        </DialogPanel>
      </div>
    </Dialog>
    </>
  );
}
