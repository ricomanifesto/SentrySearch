'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  AdjustmentsHorizontalIcon,
  CalendarDaysIcon,
  DocumentMagnifyingGlassIcon,
  EyeIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import { formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { SurfaceHeader } from '@/components/ui/SurfaceHeader';

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

const getQualityVariant = (score: number) =>
  score >= 4.0 ? 'success' : score >= 3.0 ? 'info' : score >= 2.0 ? 'warning' : 'error';

const getQualityLabel = (score: number) =>
  score >= 4.0 ? 'High confidence' : score >= 3.0 ? 'Reviewable' : score >= 2.0 ? 'Needs review' : 'Low confidence';

const formatTaxonomyLabel = (value: string) =>
  value.replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());

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
      setFilters(prev => (
        prev.query === searchInput ? prev : { ...prev, query: searchInput }
      ));
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
      {
        sort_by: filters.sortBy,
        sort_order: filters.sortOrder,
      }
    ),
  });

  const threatTypeOptions = useMemo(() => [
    { value: '', label: 'All threat types' },
    ...(filterOptions?.threat_types.map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    })) || []),
  ], [filterOptions]);

  const queryWorkbenchControls: QueryWorkbenchControl[] = useMemo(() => [
    { key: 'threatType', label: 'Threat type', options: threatTypeOptions },
    { key: 'minQuality', label: 'Minimum quality', options: qualityOptions },
    { key: 'dateRangeDays', label: 'Date range', options: dateRangeOptions },
    { key: 'sortBy', label: 'Sort by', options: sortOptions },
    { key: 'sortOrder', label: 'Order', options: sortOrderOptions },
  ], [threatTypeOptions]);

  const updateFilter = (key: keyof SearchState, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setSearchInput('');
    setFilters({
      query: '',
      threatType: '',
      minQuality: '',
      dateRangeDays: '',
      sortBy: 'created_at',
      sortOrder: 'desc',
    });
    setCurrentPage(1);
  };

  const activeFilterCount = [
    filters.query,
    filters.threatType,
    filters.minQuality,
    filters.dateRangeDays,
  ].filter(Boolean).length;
  const hasActiveFilters = activeFilterCount > 0;
  const totalReports = searchData?.pagination.total ?? 0;
  const pageStart = searchData ? ((searchData.pagination.page - 1) * searchData.pagination.limit) + 1 : 0;
  const pageEnd = searchData ? Math.min(searchData.pagination.page * searchData.pagination.limit, totalReports) : 0;

  return (
    <div data-surface="search-review-workspace" className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <SurfaceHeader
            eyebrow="Search workspace"
            title="Find saved intelligence by target and threat context"
            description="Search the fields supported by the backend contract, then reopen the source-backed report record for review."
          />

          <Card data-contract="Search.QueryWorkbenchControls.v1" className="mb-6 border-slate-200 shadow-sm">
            <CardContent className="p-4 sm:p-5">
              <div className="mb-4 flex flex-col gap-1 border-b border-slate-100 pb-4 sm:flex-row sm:items-end sm:justify-between">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Query bench</p>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    Tune target, threat, quality, and date constraints before opening a saved intelligence record.
                  </p>
                </div>
                <span className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  {hasActiveFilters ? `${activeFilterCount} active workbench constraints` : 'No workbench constraints'}
                </span>
              </div>
              <label className="relative block">
                <span className="sr-only">Search saved intelligence</span>
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="search"
                  placeholder="Search by target, category, or threat type"
                  value={searchInput}
                  onChange={handleSearchInputChange}
                  className="h-11 w-full rounded-md border border-slate-300 bg-white pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500"
                />
              </label>

              <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
                {queryWorkbenchControls.map((control) => (
                  <Select
                    key={control.key}
                    label={control.label}
                    options={control.options}
                    value={filters[control.key]}
                    onChange={(event) => updateFilter(control.key, event.target.value)}
                  />
                ))}
              </div>

              {hasActiveFilters && (
                <div className="mt-4 flex flex-col gap-3 border-t border-slate-100 pt-4 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm text-slate-600">
                    {activeFilterCount} active search {activeFilterCount === 1 ? 'constraint' : 'constraints'}
                  </span>
                  <Button variant="ghost" size="sm" onClick={clearFilters}>
                    Clear workbench constraints
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {searchData && (
            <div className="mb-4 grid gap-3 rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600 shadow-sm lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
              <span className="space-y-1">
                <span className="block">
                  <span className="font-semibold text-slate-950">Review docket:</span>{' '}
                  {totalReports === 0 ? 'no matching saved intelligence' : `showing ${pageStart}-${pageEnd} of ${totalReports} matches`}
                </span>
                <span className="block text-xs text-slate-500">
                  Sorted by {sortOptions.find(option => option.value === filters.sortBy)?.label.toLowerCase()} · {filters.sortOrder}
                </span>
              </span>
              <span className="rounded-md bg-slate-50 px-3 py-2 leading-5 text-slate-700">
                Provenance review: open matched records to inspect available detail context
              </span>
            </div>
          )}

          {isLoading ? (
            <div className="space-y-4" role="status" aria-label="Searching saved intelligence">
              {[...Array(4)].map((_, index) => (
                <Card key={index} className="border-slate-200">
                  <CardContent className="p-5">
                    <div className="animate-pulse space-y-4">
                      <div className="h-5 w-1/3 rounded bg-slate-200" />
                      <div className="h-4 w-2/3 rounded bg-slate-200" />
                      <div className="h-4 w-full rounded bg-slate-200" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : error ? (
            <Card className="border-red-200 bg-red-50">
              <CardContent className="py-10 text-center" role="alert">
                <DocumentMagnifyingGlassIcon className="mx-auto mb-4 h-12 w-12 text-red-400" />
                <h2 className="mb-2 text-lg font-semibold text-red-900">Search is unavailable</h2>
                <p className="mx-auto max-w-md text-sm leading-6 text-red-700">
                  Saved intelligence search could not be completed. Retry from this page or use the reports review queue.
                </p>
              </CardContent>
            </Card>
          ) : searchData?.reports.length === 0 ? (
            <Card className="border-slate-200">
              <CardContent className="py-12 text-center">
                <AdjustmentsHorizontalIcon className="mx-auto mb-4 h-16 w-16 text-slate-400" />
                <h2 className="mb-2 text-lg font-semibold text-slate-950">
                  {hasActiveFilters ? 'No saved intelligence matched' : 'Search is ready'}
                </h2>
                <p className="mx-auto mb-6 max-w-md text-sm leading-6 text-slate-600">
                  {hasActiveFilters
                    ? 'Adjust the target, threat type, date, or quality filters to broaden the search.'
                    : 'Enter a target, category, or threat type to search across saved reports.'}
                </p>
                {hasActiveFilters && (
                  <Button variant="outline" onClick={clearFilters}>
                    Clear workbench constraints
                  </Button>
                )}
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="space-y-4">
                {searchData?.reports.map((report) => (
                  <SearchResultRecord key={report.id} report={report} />
                ))}
              </div>

              {searchData && searchData.pagination.pages > 1 && (
                <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm text-slate-600">
                    Page {currentPage} of {searchData.pagination.pages}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      disabled={currentPage <= 1}
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      disabled={currentPage >= searchData.pagination.pages}
                      onClick={() => setCurrentPage(prev => Math.min(searchData.pagination.pages, prev + 1))}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
      </div>
    </div>
  );
}

function SearchResultRecord({ report }: { report: Report }) {
  const qualityVariant = getQualityVariant(report.quality_score);
  const qualityLabel = getQualityLabel(report.quality_score);
  const resultReviewSignals: ResultReviewSignal[] = [
    {
      label: 'Analyst confidence',
      value: `${qualityLabel} · ${report.quality_score.toFixed(1)}`,
      description: 'Quality score carried from the saved report',
    },
    {
      label: 'Provenance review',
      value: 'Open record',
      description: 'Inspect available detail context before reuse',
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
    <Card
      data-contract="Card.SearchResultRecord.v1"
      className="overflow-hidden border-slate-200 shadow-sm transition hover:border-slate-300 hover:shadow-md"
    >
      <CardContent className="p-0">
        <article className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_15rem]">
          <div className="min-w-0 p-5 sm:p-6">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <Badge variant={qualityVariant} size="sm" className="rounded-md">
                {qualityLabel} · {report.quality_score.toFixed(1)}
              </Badge>
              {report.category && (
                <Badge variant="default" size="sm" className="rounded-md">
                  {formatTaxonomyLabel(report.category)}
                </Badge>
              )}
              {report.threat_type && (
                <Badge variant="default" size="sm" className="rounded-md">
                  {formatTaxonomyLabel(report.threat_type)}
                </Badge>
              )}
            </div>

            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">
                  Decision signals
                </p>
                <h2 className="mt-1 truncate text-xl font-semibold text-slate-950">
                  {report.tool_name}
                </h2>
              </div>
              <span className="inline-flex items-center gap-1 text-sm text-slate-500">
                <CalendarDaysIcon className="h-4 w-4" />
                {formatDate(report.created_at)}
              </span>
            </div>

            <dl
              data-contract="Search.ResultReviewSignals.v1"
              className="mt-4 grid gap-px overflow-hidden rounded-md border border-slate-200 bg-slate-200 sm:grid-cols-2 xl:grid-cols-4"
            >
              {resultReviewSignals.map((signal) => (
                <div key={signal.label} className="bg-slate-50 px-3 py-3">
                  <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    {signal.label}
                  </dt>
                  <dd className="mt-1 text-sm font-semibold text-slate-950">
                    {signal.value}
                  </dd>
                  <dd className="mt-1 text-xs leading-5 text-slate-500">
                    {signal.description}
                  </dd>
                </div>
              ))}
            </dl>

            <p className="mt-4 line-clamp-2 max-w-4xl text-sm leading-6 text-slate-600">
              {report.content_preview || 'No preview was saved for this report. Open it to inspect the full intelligence record.'}
            </p>
          </div>

          <aside className="border-t border-slate-200 bg-slate-950 p-5 text-white lg:border-l lg:border-t-0">
            <p className="text-xs font-semibold uppercase tracking-wide text-cyan-200">Inspection brief</p>
            <h3 className="mt-2 text-base font-semibold">Review record</h3>
            <p className="mt-2 text-sm leading-6 text-slate-300">
              Open the saved record to inspect available detail context before reuse.
            </p>
            <Link href={`/reports/${report.id}`} className="mt-4 block">
              <Button size="sm" variant="secondary" className="min-h-10 w-full gap-2 bg-white text-slate-950 hover:bg-slate-100">
                <EyeIcon className="h-4 w-4" />
                Open intelligence record
              </Button>
            </Link>
          </aside>
        </article>
      </CardContent>
    </Card>
  );
}
