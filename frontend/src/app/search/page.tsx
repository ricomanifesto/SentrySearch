'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { MagnifyingGlassIcon, ArrowRightIcon } from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import { formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';

interface SearchState {
  query: string;
  threatType: string;
  minQuality: string;
  dateRangeDays: string;
  sortBy: string;
  sortOrder: string;
}

type QueryWorkbenchControlKey = 'threatType' | 'minQuality' | 'dateRangeDays' | 'sortBy' | 'sortOrder';

type QueryWorkbenchControl = {
  key: QueryWorkbenchControlKey;
  label: string;
  options: Array<{ value: string; label: string }>;
};

type ResultReviewSignal = {
  label: string;
  value: string;
  description: string;
};

const qualityOptions = [
  { value: '', label: 'Any quality' },
  { value: '4.0', label: '4.0+ high confidence' },
  { value: '3.0', label: '3.0+ reviewable' },
  { value: '2.0', label: '2.0+ needs review' },
];

const dateRangeOptions = [
  { value: '', label: 'Any time' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last year' },
];

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

const getQualityLabel = (score: number) =>
  score >= 4.0 ? 'High confidence' : score >= 3.0 ? 'Reviewable' : score >= 2.0 ? 'Needs review' : 'Low confidence';

const formatTaxonomyLabel = (value: string) =>
  value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

const selectClass =
  'mt-1.5 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-100';

const secondaryButtonClass =
  'inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 disabled:pointer-events-none disabled:opacity-50';

export default function SearchPage() {
  return (
    <AuthGuard>
      <SearchWorkspace />
    </AuthGuard>
  );
}

function SearchWorkspace() {
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState<SearchState>({
    query: '',
    threatType: '',
    minQuality: '',
    dateRangeDays: '',
    sortBy: 'created_at',
    sortOrder: 'desc',
  });
  const [searchInput, setSearchInput] = useState('');

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      setFilters((prev) => (prev.query === searchInput ? prev : { ...prev, query: searchInput }));
      setCurrentPage(1);
    }, 300);
    return () => window.clearTimeout(timeoutId);
  }, [searchInput]);

  const handleSearchInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchInput(event.target.value);
  };

  const { data: filterOptions } = useQuery({
    queryKey: ['search', 'filters'],
    queryFn: () => api.getSearchFilters(),
  });

  const { data: searchData, isLoading, error } = useQuery({
    queryKey: ['search', 'review-workspace', currentPage, filters],
    queryFn: () => api.searchReports(
      {
        query: filters.query || undefined,
        threat_types: filters.threatType ? [filters.threatType] : undefined,
        min_quality_score: filters.minQuality ? parseFloat(filters.minQuality) : undefined,
        date_range_days: filters.dateRangeDays ? parseInt(filters.dateRangeDays, 10) : undefined,
      },
      currentPage,
      20,
      { sort_by: filters.sortBy, sort_order: filters.sortOrder },
    ),
  });

  const threatTypeOptions = useMemo(() => [
    { value: '', label: 'All threat types' },
    ...(filterOptions?.threat_types.map((type) => ({ value: type, label: formatTaxonomyLabel(type) })) || []),
  ], [filterOptions]);

  const queryWorkbenchControls: QueryWorkbenchControl[] = useMemo(() => [
    { key: 'threatType', label: 'Threat type', options: threatTypeOptions },
    { key: 'minQuality', label: 'Minimum quality', options: qualityOptions },
    { key: 'dateRangeDays', label: 'Date range', options: dateRangeOptions },
    { key: 'sortBy', label: 'Sort by', options: sortOptions },
    { key: 'sortOrder', label: 'Order', options: sortOrderOptions },
  ], [threatTypeOptions]);

  const updateFilter = (key: keyof SearchState, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setSearchInput('');
    setFilters({ query: '', threatType: '', minQuality: '', dateRangeDays: '', sortBy: 'created_at', sortOrder: 'desc' });
    setCurrentPage(1);
  };

  const activeFilterCount = [filters.query, filters.threatType, filters.minQuality, filters.dateRangeDays].filter(Boolean).length;
  const hasActiveFilters = activeFilterCount > 0;
  const totalReports = searchData?.pagination.total ?? 0;
  const pageStart = searchData ? ((searchData.pagination.page - 1) * searchData.pagination.limit) + 1 : 0;
  const pageEnd = searchData ? Math.min(searchData.pagination.page * searchData.pagination.limit, totalReports) : 0;

  return (
    <main data-surface="search-review-workspace" className="overflow-x-hidden bg-[var(--surface-0)]">
      <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
        <div className="max-w-2xl">
          <p className="text-sm font-medium text-blue-700">Search workspace</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Find saved intelligence</h1>
          <p className="mt-4 text-lg leading-8 text-zinc-600">
            Search saved reports by target and threat context, then reopen the
            source-backed record for review.
          </p>
        </div>

        <section data-contract="Search.QueryWorkbenchControls.v1" className="mt-8 rounded-xl border border-zinc-200 bg-white p-5">
          <label className="relative block">
            <span className="sr-only">Search saved intelligence</span>
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search by target, category, or threat type"
              value={searchInput}
              onChange={handleSearchInputChange}
              className="h-11 w-full rounded-lg border border-zinc-300 bg-white pl-10 pr-4 text-sm text-zinc-950 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            />
          </label>

          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
            {queryWorkbenchControls.map((control) => (
              <label key={control.key} className="block">
                <span className="block text-sm font-medium text-zinc-800">{control.label}</span>
                <select
                  value={filters[control.key]}
                  onChange={(event) => updateFilter(control.key, event.target.value)}
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
            <div className="mt-4 flex items-center justify-between gap-3 border-t border-zinc-100 pt-4">
              <span className="text-sm text-zinc-600">
                {activeFilterCount} active workbench {activeFilterCount === 1 ? 'constraint' : 'constraints'}
              </span>
              <button type="button" onClick={clearFilters} className="text-sm font-medium text-blue-700 hover:underline">
                Clear workbench constraints
              </button>
            </div>
          )}
        </section>

        {searchData && (
          <p className="mt-4 text-sm text-zinc-500">
            {totalReports === 0 ? 'No matching saved intelligence' : `Showing ${pageStart}–${pageEnd} of ${totalReports} matches`}
          </p>
        )}

        <div className="mt-4">
          {isLoading ? (
            <div className="space-y-4" role="status" aria-label="Searching saved intelligence">
              {[...Array(4)].map((_, index) => (
                <div key={index} className="h-28 animate-pulse rounded-xl bg-zinc-100" />
              ))}
            </div>
          ) : error ? (
            <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-6 text-center">
              <h2 className="text-base font-semibold text-red-900">Search is unavailable</h2>
              <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-red-700">
                Saved intelligence search could not be completed. Retry from this page, or use the reports review queue.
              </p>
            </div>
          ) : searchData?.reports.length === 0 ? (
            <div className="rounded-xl border border-dashed border-zinc-300 px-6 py-12 text-center">
              <h2 className="text-base font-semibold text-zinc-950">
                {hasActiveFilters ? 'No saved intelligence matched' : 'Search is ready'}
              </h2>
              <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500">
                {hasActiveFilters
                  ? 'Adjust the target, threat type, date, or quality filters to broaden the search.'
                  : 'Enter a target, category, or threat type to search across saved reports.'}
              </p>
              {hasActiveFilters && (
                <button type="button" onClick={clearFilters} className={`${secondaryButtonClass} mt-6`}>
                  Clear workbench constraints
                </button>
              )}
            </div>
          ) : (
            <>
              <div className="space-y-4">
                {searchData?.reports.map((report) => (
                  <SearchResultRecord key={report.id} report={report} />
                ))}
              </div>

              {searchData && searchData.pagination.pages > 1 && (
                <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm text-zinc-600">Page {currentPage} of {searchData.pagination.pages}</span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={currentPage <= 1}
                      onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                      className={secondaryButtonClass}
                    >
                      Previous
                    </button>
                    <button
                      type="button"
                      disabled={currentPage >= searchData.pagination.pages}
                      onClick={() => setCurrentPage((prev) => Math.min(searchData.pagination.pages, prev + 1))}
                      className={secondaryButtonClass}
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

function SearchResultRecord({ report }: { report: Report }) {
  const qualityLabel = getQualityLabel(report.quality_score);
  const resultReviewSignals: ResultReviewSignal[] = [
    {
      label: 'Analyst confidence',
      value: `${qualityLabel} · ${report.quality_score.toFixed(1)}`,
      description: 'Quality score carried from the saved report',
    },
    {
      label: 'Generated',
      value: formatRelativeTime(report.created_at),
      description: formatDate(report.created_at),
    },
    {
      label: 'Runtime',
      value: report.processing_time_ms ? formatProcessingTime(report.processing_time_ms) : 'Not recorded',
      description: 'Generation duration',
    },
  ];

  return (
    <article
      data-contract="Card.SearchResultRecord.v1"
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
            {report.category && (
              <span className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{formatTaxonomyLabel(report.category)}</span>
            )}
            {report.threat_type && (
              <span className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">{formatTaxonomyLabel(report.threat_type)}</span>
            )}
          </div>
        </div>
        <Link href={`/reports/${report.id}`} className={`${secondaryButtonClass} shrink-0`}>
          Open record
          <ArrowRightIcon className="h-4 w-4" aria-hidden="true" />
        </Link>
      </div>

      <dl
        data-contract="Search.ResultReviewSignals.v1"
        className="mt-4 grid gap-px overflow-hidden rounded-lg border border-zinc-200 bg-zinc-200 sm:grid-cols-3"
      >
        {resultReviewSignals.map((signal) => (
          <div key={signal.label} className="bg-white px-3 py-3">
            <dt className="text-sm text-zinc-500">{signal.label}</dt>
            <dd className="mt-1 text-sm font-medium text-zinc-950">{signal.value}</dd>
            <dd className="mt-0.5 text-sm leading-5 text-zinc-500">{signal.description}</dd>
          </div>
        ))}
      </dl>

      <p className="mt-4 line-clamp-2 text-sm leading-6 text-zinc-600">
        {report.content_preview || 'No preview was saved for this report. Open it to inspect the full intelligence record.'}
      </p>
    </article>
  );
}
