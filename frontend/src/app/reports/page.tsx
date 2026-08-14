'use client';

import React, { Suspense, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import {
  FunnelIcon,
  MagnifyingGlassIcon,
  PlusIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import {
  countActiveReportFilters,
  dateRangeFilterOptions,
  defaultReportQuery,
  formatTaxonomyLabel,
  getQualityLabel,
  qualityFilterOptions,
  reportSortOptions,
  reportQueryFromSearchParams,
  reportQuerySearchParams,
  sortOrderOptions,
  toReportSort,
  toSearchFilters,
  type ReportQueryState,
} from '@/lib/report-query';
import { formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { getReviewStatusClasses, getReviewStatusLabel } from '@/lib/report-status';

type ReviewQueueControlKey = 'threatType' | 'minQuality' | 'dateRangeDays' | 'sortBy' | 'sortOrder';

type ReviewQueueControl = {
  key: ReviewQueueControlKey;
  label: string;
  options: Array<{ value: string; label: string }>;
};

type ReportRecordSignal = {
  label: string;
  value: string;
  detail: string;
};

const selectClass =
  'mt-1.5 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-100';

const secondaryButtonClass =
  'inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400';

const primaryButtonClass =
  'inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2';

export default function ReportsPage() {
  return (
    <AuthGuard>
      <Suspense fallback={<ReportsLoadingState />}>
        <ReportsWorkspace />
      </Suspense>
    </AuthGuard>
  );
}

function ReportsLoadingState() {
  return (
    <main className="min-h-[60vh] bg-[var(--surface-0)] px-6 py-16" role="status" aria-label="Loading review queue">
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="h-10 w-64 animate-pulse rounded bg-zinc-200" />
        {[...Array(4)].map((_, index) => <div key={index} className="h-32 animate-pulse rounded-xl bg-zinc-100" />)}
      </div>
    </main>
  );
}

function ReportsWorkspace() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const filters = useMemo(
    () => reportQueryFromSearchParams(new URLSearchParams(searchParams.toString())),
    [searchParams],
  );
  const currentPage = Math.max(1, Number.parseInt(searchParams.get('page') || '1', 10) || 1);
  const [showFilters, setShowFilters] = useState(false);

  const replaceQuery = React.useCallback((nextFilters: ReportQueryState, page = 1) => {
    const params = reportQuerySearchParams(nextFilters, page).toString();
    router.replace(params ? `${pathname}?${params}` : pathname, { scroll: false });
  }, [pathname, router]);

  const { data: reportsData, isLoading, error } = useQuery({
    queryKey: ['reports', 'list', currentPage, filters],
    queryFn: () => api.searchReports(
      toSearchFilters(filters),
      currentPage,
      20,
      toReportSort(filters),
    ),
  });

  const { data: filterOptions } = useQuery({
    queryKey: ['search', 'filters'],
    queryFn: () => api.getSearchFilters(),
  });

  const threatTypeOptions = useMemo(() => [
    { value: '', label: 'All threat types' },
    ...(filterOptions?.threat_types.map((type) => ({
      value: type,
      label: formatTaxonomyLabel(type),
    })) || []),
  ], [filterOptions]);

  const reviewQueueControls: ReviewQueueControl[] = useMemo(() => [
    { key: 'threatType', label: 'Threat type', options: threatTypeOptions },
    { key: 'minQuality', label: 'Minimum quality', options: qualityFilterOptions },
    { key: 'dateRangeDays', label: 'Date range', options: dateRangeFilterOptions },
    { key: 'sortBy', label: 'Sort by', options: reportSortOptions },
    { key: 'sortOrder', label: 'Order', options: sortOrderOptions },
  ], [threatTypeOptions]);

  const handleFilterChange = (key: ReviewQueueControlKey, value: string) => {
    replaceQuery({ ...filters, [key]: value } as ReportQueryState, 1);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    replaceQuery({ ...filters, query: e.target.value }, 1);
  };

  const clearFilters = () => {
    replaceQuery({ ...defaultReportQuery }, 1);
  };

  const activeFilterCount = countActiveReportFilters(filters);
  const hasActiveFilters = activeFilterCount > 0;
  const totalReports = reportsData?.pagination.total ?? 0;
  const pageStart = reportsData ? ((reportsData.pagination.page - 1) * reportsData.pagination.limit) + 1 : 0;
  const pageEnd = reportsData ? Math.min(reportsData.pagination.page * reportsData.pagination.limit, reportsData.pagination.total) : 0;

  return (
      <main data-surface="report-review-queue" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-2xl">
              <p className="text-sm font-medium text-blue-700">Saved intelligence</p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Review queue</h1>
              <p className="mt-4 text-lg leading-8 text-zinc-600">
                Search saved threat profiles, compare report quality, and reopen each
                record with its source-backed context.
              </p>
            </div>
            <Link href="/generate" className={primaryButtonClass}>
              <PlusIcon className="h-5 w-5" aria-hidden="true" />
              Generate report
            </Link>
          </div>

          <section data-contract="Reports.ReviewQueueControls.v1" className="mt-8 rounded-xl border border-zinc-200 bg-white p-5">
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
              <label className="relative block">
                <span className="sr-only">Search reports</span>
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" aria-hidden="true" />
                <input
                  type="search"
                  placeholder="Search by target, category, or threat type"
                  value={filters.query}
                  onChange={handleSearchChange}
                  className="h-11 w-full rounded-lg border border-zinc-300 bg-white pl-10 pr-4 text-sm text-zinc-950 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                />
              </label>
              <button
                type="button"
                onClick={() => setShowFilters(!showFilters)}
                aria-expanded={showFilters}
                className={`${secondaryButtonClass} w-full lg:w-auto`}
              >
                <FunnelIcon className="h-4 w-4" aria-hidden="true" />
                Tune queue
                {hasActiveFilters && (
                  <span className="rounded-md bg-blue-50 px-2 py-0.5 text-sm font-medium text-blue-700">{activeFilterCount}</span>
                )}
              </button>
            </div>

            {showFilters && (
              <div className="mt-4 border-t border-zinc-100 pt-4">
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
                  {reviewQueueControls.map((control) => (
                    <label key={control.key} className="block">
                      <span className="block text-sm font-medium text-zinc-800">{control.label}</span>
                      <select
                        value={filters[control.key]}
                        onChange={(e) => handleFilterChange(control.key, e.target.value)}
                        className={selectClass}
                      >
                        {control.options.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </label>
                  ))}
                </div>
                {hasActiveFilters && (
                  <button type="button" onClick={clearFilters} className="mt-4 text-sm font-medium text-blue-700 hover:underline">
                    Clear queue constraints
                  </button>
                )}
              </div>
            )}
          </section>

          {reportsData && (
            <p className="mt-4 text-sm text-zinc-500">
              {totalReports === 0
                ? 'No saved reports'
                : `Showing ${pageStart}–${pageEnd} of ${totalReports} saved reports`}
            </p>
          )}

          <div className="mt-4">
            {isLoading ? (
              <div className="space-y-4" role="status" aria-label="Loading reports">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="h-28 animate-pulse rounded-xl bg-zinc-100" />
                ))}
              </div>
            ) : error ? (
              <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-6 text-center">
                <h2 className="text-base font-semibold text-red-900">Reports could not be loaded</h2>
                <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-red-700">
                  The saved report list is unavailable. Retry from this page, or generate a new report if the issue persists.
                </p>
              </div>
            ) : reportsData?.reports.length === 0 ? (
              <div className="rounded-xl border border-dashed border-zinc-300 px-6 py-12 text-center">
                <h2 className="text-base font-semibold text-zinc-950">
                  {hasActiveFilters ? 'No matching reports' : 'No saved reports yet'}
                </h2>
                <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500">
                  {hasActiveFilters
                    ? 'Adjust the search or filters to broaden the review queue.'
                    : 'Generate your first report to start building the review queue.'}
                </p>
                <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
                  {hasActiveFilters && (
                    <button type="button" onClick={clearFilters} className={secondaryButtonClass}>
                      Clear queue constraints
                    </button>
                  )}
                  <Link href="/generate" className={primaryButtonClass}>Generate report</Link>
                </div>
              </div>
            ) : (
              <>
                <div className="space-y-4">
                  {reportsData?.reports.map((report) => (
                    <ReportReviewRecord key={report.id} report={report} />
                  ))}
                </div>

                {reportsData && reportsData.pagination.pages > 1 && (
                  <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <span className="text-sm text-zinc-600">
                      Page {currentPage} of {reportsData.pagination.pages}
                    </span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={currentPage <= 1}
                        onClick={() => replaceQuery(filters, Math.max(1, currentPage - 1))}
                        className={`${secondaryButtonClass} disabled:pointer-events-none disabled:opacity-50`}
                      >
                        Previous
                      </button>
                      <button
                        type="button"
                        disabled={currentPage >= reportsData.pagination.pages}
                        onClick={() => replaceQuery(filters, Math.min(reportsData.pagination.pages, currentPage + 1))}
                        className={`${secondaryButtonClass} disabled:pointer-events-none disabled:opacity-50`}
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </main>
  );
}

function ReportReviewRecord({ report }: { report: Report }) {
  const qualityLabel = getQualityLabel(report.quality_score);
  const qualityValue = report.quality_score == null
    ? qualityLabel
    : `${qualityLabel} · ${report.quality_score.toFixed(2)}`;
  const reportRecordSignals: ReportRecordSignal[] = [
    {
      label: 'Report quality',
      value: qualityValue,
      detail: 'Quality score carried from the saved report',
    },
    {
      label: 'Generated',
      value: formatRelativeTime(report.created_at),
      detail: formatDate(report.created_at),
    },
    {
      label: 'Runtime',
      value: report.processing_time_ms ? formatProcessingTime(report.processing_time_ms) : 'Not recorded',
      detail: 'Generation duration',
    },
  ];

  return (
    <article
      data-contract="Card.ReportReviewRecord.v1"
      className="rounded-xl border border-zinc-200 bg-white p-5 transition-colors hover:border-zinc-300 sm:p-6"
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <Link href={`/reports/${report.id}`} className="block truncate text-xl font-semibold text-zinc-950 hover:text-blue-700">
            {report.tool_name}
          </Link>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">
              {qualityValue}
            </span>
            <span className={`rounded-md px-2 py-1 text-sm font-medium ${getReviewStatusClasses(report.review_status)}`}>
              {getReviewStatusLabel(report.review_status)}
            </span>
            {report.category ? (
              <span className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{formatTaxonomyLabel(report.category)}</span>
            ) : null}
            {report.threat_type ? (
              <span className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{formatTaxonomyLabel(report.threat_type)}</span>
            ) : null}
          </div>
        </div>
        <Link href={`/reports/${report.id}`} className={`${secondaryButtonClass} shrink-0`}>
          Open record
          <ArrowRightIcon className="h-4 w-4" aria-hidden="true" />
        </Link>
      </div>

      <dl
        data-contract="Reports.ReviewRecordSignals.v1"
        className="mt-4 grid gap-px overflow-hidden rounded-lg border border-zinc-200 bg-zinc-200 sm:grid-cols-3"
      >
        {reportRecordSignals.map((signal) => (
          <div key={signal.label} className="bg-white px-3 py-3">
            <dt className="text-sm text-zinc-500">{signal.label}</dt>
            <dd className="mt-1 text-sm font-medium text-zinc-950">{signal.value}</dd>
            <dd className="mt-0.5 text-sm leading-5 text-zinc-500">{signal.detail}</dd>
          </div>
        ))}
      </dl>

      <p className="mt-4 line-clamp-2 text-sm leading-6 text-zinc-600">
        {report.content_preview || 'No preview was saved for this report. Open it to review the full intelligence record.'}
      </p>
    </article>
  );
}
