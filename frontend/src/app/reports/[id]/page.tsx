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

import { api, type GenerationStage, type ReportDetail, type StoredAnalystDisposition } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, downloadAsFile } from '@/lib/utils';
import { SAMPLE_REPORT } from '@/lib/sample-report';
import { formatTaxonomyLabel, getQualityLabel } from '@/lib/report-query';
import { getReportSectionLinks, splitReportContent } from '@/lib/report-content';
import { getReviewAttentionSummary } from '@/lib/review-attention';
import { getGenerationFailurePresentation } from '@/lib/generation-failure';
import { AuthGuard } from '@/components/AuthGuard';
import { ReportNarrative } from '@/components/report/ReportNarrative';
import { SourceEvidence } from '@/components/report/SourceEvidence';
import { GenerationProgress } from '@/components/report/GenerationProgress';
import { RouteProvenance } from '@/components/report/RouteProvenance';
import { ReviewStatusBanner } from '@/components/report/ReviewStatusBanner';
import { AnalystDispositionPanel } from '@/components/report/AnalystDispositionPanel';

const LOCAL_REPORT_DETAIL_FIXTURE_ID = 'local-visual-fixture';
const LOCAL_REVIEW_ATTENTION_FIXTURE_ID = 'local-review-attention-fixture';
const LOCAL_FAILED_GENERATION_FIXTURE_ID = 'local-failed-generation-fixture';

const localReportDetailFixture: ReportDetail = {
  ...SAMPLE_REPORT,
  id: LOCAL_REPORT_DETAIL_FIXTURE_ID,
  quality_score: null,
  evaluation_status: 'failed',
  evaluation_error_code: 'evaluator_unavailable',
  evaluation_attempts: 1,
  review_status: 'needs_evaluation',
  eligible_for_judgment: false,
  classification_status: 'recorded',
  quality_assessment: null,
  research_route: {
    requested_models: ['google/gemma-4-26b-a4b-it:free'],
    requested_providers: ['google-ai-studio'],
    selected_models: ['google/gemma-4-26b-a4b-it'],
    actual_models: ['google/gemma-4-26b-a4b-it'],
    providers: ['OpenAI'],
    used_fallback: true,
    request_count: 3,
  },
  synthesis_route: {
    requested_models: ['google/gemini-2.5-flash'],
    requested_providers: ['google-ai-studio'],
    selected_models: ['google/gemini-2.5-flash'],
    actual_models: ['google/gemini-2.5-flash'],
    providers: ['google-ai-studio'],
    used_fallback: false,
    request_count: 1,
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

const localReviewAttentionFixture: ReportDetail = {
  ...SAMPLE_REPORT,
  id: LOCAL_REVIEW_ATTENTION_FIXTURE_ID,
  classification_status: 'reconciled',
  review_status: 'needs_attention',
  analyst_disposition: 'needs_revision',
  current_disposition: {
    id: 'local-disposition-needs-revision',
    disposition: 'needs_revision',
    note: 'Reconcile the observed-use timeline and directly source the detection claim.',
    evaluation_attempt: 1,
    created_at: '2026-08-14T16:20:00.000Z',
    is_current: true,
  },
  disposition_history: [
    {
      id: 'local-disposition-accepted',
      disposition: 'accepted',
      note: 'Initial review accepted the narrative before the consistency check was rerun.',
      evaluation_attempt: 1,
      created_at: '2026-08-14T15:45:00.000Z',
      is_current: false,
    },
    {
      id: 'local-disposition-needs-revision',
      disposition: 'needs_revision',
      note: 'Reconcile the observed-use timeline and directly source the detection claim.',
      evaluation_attempt: 1,
      created_at: '2026-08-14T16:20:00.000Z',
      is_current: true,
    },
  ],
  quality_assessment: {
    overall_score: 3.5,
    summary: {
      total_sections: 7,
      passed_sections: 5,
      enhance_sections: 2,
      failed_sections: 0,
      unavailable_sections: 0,
    },
    consistency: {
      consistency_score: 3.5,
      inconsistencies: [
        'The observed-use timeline needs reconciliation with the profile metadata date.',
        'One detection claim needs a direct source link before operational reuse.',
      ],
      recommendations: ['Verify the timeline and source the detection claim.'],
    },
  },
};

const localFailedGenerationFixture: ReportDetail = {
  ...SAMPLE_REPORT,
  id: LOCAL_FAILED_GENERATION_FIXTURE_ID,
  tool_name: 'Havoc',
  status: 'failed',
  generation_stage: 'failed',
  generation_failure_stage: 'validating',
  generation_error_code: 'provider_unavailable',
  generation_retryable: true,
  generation_failure: {
    schema_version: 1,
    error_code: 'provider_unavailable',
    retryable: true,
    stage: 'validating',
    route_attempts: [
      {
        requested_model: 'google/gemma-4-26b-a4b-it:free',
        selected_model: 'google/gemma-4-26b-a4b-it:free',
        provider: 'google-ai-studio',
        outcome: 'failed',
        error_code: 'provider_unavailable',
        retryable: true,
      },
    ],
  },
  evaluation_status: 'unrecorded',
  evaluation_attempts: 0,
  review_status: 'generation_failed',
  eligible_for_judgment: false,
  classification_status: 'unrecorded',
  quality_score: null,
  quality_assessment: null,
  markdown_content: undefined,
  web_sources: [],
};

function generationFailureSentence(stage?: GenerationStage | null): string {
  switch (stage) {
    case 'queued': return 'This run stopped while preparing research.';
    case 'researching': return 'This run stopped while researching sources.';
    case 'synthesizing': return 'This run stopped while synthesizing the narrative.';
    case 'validating': return 'This run stopped while validating report sections.';
    case 'finalizing': return 'This run stopped while saving the review record.';
    default: return 'This run stopped before a generation stage was recorded.';
  }
}

function classificationDetail(status: ReportDetail['classification_status']): string {
  switch (status) {
    case 'recorded': return 'Stored structured classification';
    case 'reconciled': return 'Recovered from the saved structured extraction';
    case 'unmapped': return 'Stored classification exists but does not map to the canonical taxonomy';
    case 'unrecorded': return 'Legacy record without structured classification provenance';
  }
}

function DeleteReportDialog({
  open,
  toolName,
  pending,
  failed,
  onClose,
  onDelete,
}: {
  open: boolean;
  toolName: string;
  pending: boolean;
  failed: boolean;
  onClose: () => void;
  onDelete: () => void;
}) {
  return (
    <Dialog open={open} onClose={() => { if (!pending) onClose(); }} className="relative z-50">
      <div className="fixed inset-0 bg-zinc-950/40" aria-hidden="true" />
      <div className="fixed inset-0 flex items-center justify-center overflow-y-auto p-4">
        <DialogPanel className="w-full max-w-md rounded-xl border border-zinc-200 bg-white p-6 shadow-xl">
          <DialogTitle className="text-xl font-semibold text-zinc-950">Delete this report?</DialogTitle>
          <p className="mt-3 text-sm leading-6 text-zinc-600">
            The saved record and review history for {toolName} will be permanently removed.
          </p>
          {failed ? (
            <p className="mt-3 text-sm text-red-700" role="alert">
              The report could not be deleted. The saved record is still available.
            </p>
          ) : null}
          <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
            <button type="button" disabled={pending} onClick={onClose} className={secondaryButtonClass}>
              Keep report
            </button>
            <button
              type="button"
              disabled={pending}
              onClick={onDelete}
              className="inline-flex h-10 items-center justify-center rounded-lg bg-red-700 px-4 text-sm font-medium text-white transition-colors hover:bg-red-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400 disabled:pointer-events-none disabled:opacity-50"
            >
              {pending ? 'Deleting report…' : 'Delete permanently'}
            </button>
          </div>
        </DialogPanel>
      </div>
    </Dialog>
  );
}

const secondaryButtonClass =
  'inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 disabled:pointer-events-none disabled:opacity-50';

export default function ReportDetailPage() {
  const params = useParams();
  const reportId = params?.id as string;
  const fixtureReport = process.env.NODE_ENV === 'development'
    ? reportId === LOCAL_REPORT_DETAIL_FIXTURE_ID
      ? localReportDetailFixture
      : reportId === LOCAL_REVIEW_ATTENTION_FIXTURE_ID
        ? localReviewAttentionFixture
        : reportId === LOCAL_FAILED_GENERATION_FIXTURE_ID
          ? localFailedGenerationFixture
        : undefined
    : undefined;

  return fixtureReport ? (
    <ReportDetailContent fixtureReport={fixtureReport} />
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
  const dispositionMutation = useMutation({
    mutationFn: ({ disposition, note }: { disposition: StoredAnalystDisposition; note: string }) => (
      api.appendReportDisposition(reportId, disposition, note)
    ),
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
    const failurePresentation = getGenerationFailurePresentation(
      report.generation_error_code,
      report.generation_retryable,
    );
    return (
      <>
      <main data-surface="report-detail-record" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-2xl px-6 py-16 lg:px-8">
          <section
            data-contract="Report.GenerationFailed.v1"
            className="rounded-xl border border-red-200 bg-red-50 px-6 py-10 text-center"
            role="alert"
          >
            <p className="text-sm font-medium text-red-800">{report.tool_name}</p>
            <h1 className="mt-2 text-2xl font-semibold text-red-900">{failurePresentation.heading}</h1>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-red-700">
              {generationFailureSentence(report.generation_failure_stage)}{' '}{failurePresentation.detail}
            </p>
            <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
              <button
                type="button"
                onClick={() => router.push(`/generate?target=${encodeURIComponent(report.tool_name)}`)}
                className={secondaryButtonClass}
              >
                {failurePresentation.retryLabel}
              </button>
              <button type="button" onClick={() => router.push('/reports?review_state=generation_failed')} className={secondaryButtonClass}>
                View failed runs
              </button>
              <button
                type="button"
                onClick={handleDelete}
                className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-red-300 bg-white px-4 text-sm font-medium text-red-700 hover:bg-red-100"
              >
                <TrashIcon className="h-4 w-4" aria-hidden="true" />
                Delete failed record
              </button>
            </div>
          </section>
        </div>
      </main>
      <DeleteReportDialog
        open={deleteConfirmationOpen}
        toolName={report.tool_name}
        pending={deleteMutation.isPending}
        failed={deleteMutation.isError}
        onClose={() => setDeleteConfirmationOpen(false)}
        onDelete={() => deleteMutation.mutate()}
      />
      </>
    );
  }

  const qualityScore = report.quality_score;
  const qualityLabel = getQualityLabel(qualityScore);
  const contentParts = splitReportContent(report.markdown_content || '');
  const sectionLinks = getReportSectionLinks(contentParts.narrative);
  const attentionSummary = getReviewAttentionSummary(
    report.quality_assessment,
    report.web_sources.length,
    report.analyst_disposition,
  );

  const recordSummarySignals = [
    {
      label: 'Content quality',
      value: qualityScore == null ? qualityLabel : `${qualityScore.toFixed(2)} / 5.00`,
      detail: qualityLabel,
    },
    {
      label: 'Category',
      value: formatTaxonomyLabel(report.category || 'unclassified'),
      detail: classificationDetail(report.classification_status),
    },
    {
      label: 'Threat type',
      value: formatTaxonomyLabel(report.threat_type || 'unclassified'),
      detail: classificationDetail(report.classification_status),
    },
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
          researchRoute={report.research_route}
          synthesisRoute={report.synthesis_route}
          evaluationRoute={report.evaluation_route}
        />

        <ReviewStatusBanner
          status={report.review_status}
          analystDisposition={report.analyst_disposition}
          retryPending={evaluationMutation.isPending}
          retryDisabled={isFixtureRecord}
          retryError={evaluationMutation.isError}
          onRetry={() => evaluationMutation.mutate()}
          attention={attentionSummary}
        />

        <AnalystDispositionPanel
          key={`${report.evaluation_attempts}-${report.current_disposition?.id ?? 'unreviewed'}`}
          report={report}
          disabled={isFixtureRecord}
          pending={dispositionMutation.isPending}
          failed={dispositionMutation.isError}
          reevaluationPending={evaluationMutation.isPending}
          onRecord={(disposition, note) => dispositionMutation.mutate({ disposition, note })}
          onReevaluate={() => evaluationMutation.mutate()}
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

        {sectionLinks.length > 0 ? (
          <details className="mt-6 rounded-xl border border-zinc-200 bg-white px-5 py-4">
            <summary className="cursor-pointer text-sm font-medium text-zinc-950 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
              Report outline · {sectionLinks.length} sections
            </summary>
            <nav aria-label="Narrative outline" className="mt-3 grid gap-2 sm:grid-cols-2">
              {sectionLinks.map((section) => (
                <a key={section.id} href={`#${section.id}`} className="text-sm text-blue-700 hover:underline">
                  {section.label}
                </a>
              ))}
            </nav>
          </details>
        ) : null}

        <div className="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <section id="intelligence-narrative" className="order-last min-w-0 scroll-mt-6 rounded-xl border border-zinc-200 bg-white p-6 lg:order-first">
            <p className="text-base font-semibold text-zinc-950">Intelligence narrative</p>
            {report.markdown_content ? (
              <ReportNarrative
                markdown={contentParts.narrative}
                claimAttributions={report.claim_attributions}
              />
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
              <SourceEvidence
                sources={report.web_sources}
                attributionStatus={report.claim_attribution_status}
                attributionVersion={report.claim_attribution_version}
              />
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
    <DeleteReportDialog
      open={deleteConfirmationOpen}
      toolName={report.tool_name}
      pending={deleteMutation.isPending}
      failed={deleteMutation.isError}
      onClose={() => setDeleteConfirmationOpen(false)}
      onDelete={() => deleteMutation.mutate()}
    />
    </>
  );
}
