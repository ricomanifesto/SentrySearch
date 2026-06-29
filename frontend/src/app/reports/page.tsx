'use client';

import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  FunnelIcon,
  MagnifyingGlassIcon,
  PlusIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import { debounce, formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';

interface FilterState {
  query: string;
  threat_type: string;
  min_quality: string;
  sort_by: string;
  sort_order: string;
}

type ReviewQueueControlKey = 'threat_type' | 'min_quality' | 'sort_by' | 'sort_order';

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

const sortOptions = [
  { value: 'created_at', label: 'Date created' },
  { value: 'quality_score', label: 'Quality score' },
  { value: 'tool_name', label: 'Target name' },
  { value: 'processing_time_ms', label: 'Processing time' },
];

const sortOrderOptions = [
  { value: 'desc', label: 'Descending' },
  { value: 'asc', label: 'Ascending' },
];

const qualityOptions = [
  { value: '', label: 'Any quality' },
  { value: '4.0', label: '4.0+ high confidence' },
  { value: '3.0', label: '3.0+ reviewable' },
  { value: '2.0', label: '2.0+ needs review' },
  { value: '1.0', label: '1.0+ low confidence' },
];

const getQualityLabel = (score: number) =>
  score >= 4.0 ? 'High confidence' : score >= 3.0 ? 'Reviewable' : score >= 2.0 ? 'Needs review' : 'Low confidence';

const formatTaxonomyLabel = (value: string) =>
  value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

const selectClass =
  'mt-1.5 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-100';

const secondaryButtonClass =
  'inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400';

const primaryButtonClass =
  'inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2';

export default function ReportsPage() {
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState<FilterState>({
    query: '',
    threat_type: '',
    min_quality: '',
    sort_by: 'created_at',
    sort_order: 'desc',
  });
  const [showFilters, setShowFilters] = useState(false);

  const debouncedSearch = useMemo(
    () => debounce((query: unknown) => {
      setFilters((prev) => ({ ...prev, query: query as string }));
      setCurrentPage(1);
    }, 300),
    [],
  );

  const { data: reportsData, isLoading, error } = useQuery({
    queryKey: ['reports', 'list', currentPage, filters],
    queryFn: () => api.listReports(currentPage, 20, {
      query: filters.query || undefined,
      threat_type: filters.threat_type || undefined,
      min_quality: filters.min_quality ? parseFloat(filters.min_quality) : undefined,
      sort_by: filters.sort_by,
      sort_order: filters.sort_order,
    }),
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
    { key: 'threat_type', label: 'Threat type', options: threatTypeOptions },
    { key: 'min_quality', label: 'Minimum quality', options: qualityOptions },
    { key: 'sort_by', label: 'Sort by', options: sortOptions },
    { key: 'sort_order', label: 'Order', options: sortOrderOptions },
  ], [threatTypeOptions]);

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    debouncedSearch(e.target.value);
  };

  const clearFilters = () => {
    setFilters({ query: '', threat_type: '', min_quality: '', sort_by: 'created_at', sort_order: 'desc' });
    setCurrentPage(1);
  };

  const hasActiveFilters = Boolean(filters.query || filters.threat_type || filters.min_quality);
  const activeFilterCount = [filters.query, filters.threat_type, filters.min_quality].filter(Boolean).length;
  const totalReports = reportsData?.pagination.total ?? 0;
  const pageStart = reportsData ? ((reportsData.pagination.page - 1) * reportsData.pagination.limit) + 1 : 0;
  const pageEnd = reportsData ? Math.min(reportsData.pagination.page * reportsData.pagination.limit, reportsData.pagination.total) : 0;

  return (
    <AuthGuard>
      <main data-surface="report-review-queue" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-2xl">
              <p className="text-sm font-medium text-blue-700">Saved intelligence</p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Review queue</h1>
              <p className="mt-4 text-lg leading-8 text-zinc-600">
                Search saved threat profiles, compare confidence, and reopen each
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
                  defaultValue={filters.query}
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
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
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
                        onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                        className={`${secondaryButtonClass} disabled:pointer-events-none disabled:opacity-50`}
                      >
                        Previous
                      </button>
                      <button
                        type="button"
                        disabled={currentPage >= reportsData.pagination.pages}
                        onClick={() => setCurrentPage((prev) => Math.min(reportsData.pagination.pages, prev + 1))}
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
    </AuthGuard>
  );
}

function ReportReviewRecord({ report }: { report: Report }) {
  const qualityLabel = getQualityLabel(report.quality_score);
  const reportRecordSignals: ReportRecordSignal[] = [
    {
      label: 'Analyst confidence',
      value: `${qualityLabel} · ${report.quality_score.toFixed(1)}`,
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
              {qualityLabel} · {report.quality_score.toFixed(1)}
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
