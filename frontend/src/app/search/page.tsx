'use client';

import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  AdjustmentsHorizontalIcon,
  CalendarDaysIcon,
  DocumentMagnifyingGlassIcon,
  EyeIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { debounce, formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';

interface SearchState {
  query: string;
  threatType: string;
  minQuality: string;
  dateRangeDays: string;
  sortBy: string;
  sortOrder: string;
}

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

export default function SearchPage() {
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState<SearchState>({
    query: '',
    threatType: '',
    minQuality: '',
    dateRangeDays: '',
    sortBy: 'created_at',
    sortOrder: 'desc',
  });

  const debouncedSearch = useMemo(
    () => debounce((query: unknown) => {
      setFilters(prev => ({ ...prev, query: query as string }));
      setCurrentPage(1);
    }, 300),
    []
  );

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

  const updateFilter = (key: keyof SearchState, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const clearFilters = () => {
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
    <AuthGuard>
      <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mb-8 max-w-3xl">
            <Badge variant="info" size="sm" className="mb-3 rounded-md">
              Search workspace
            </Badge>
            <h1 className="text-2xl font-semibold leading-tight text-slate-950 sm:text-4xl">
              Find saved intelligence by target and threat context
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              Search the fields supported by the backend contract, then reopen the source-backed report record for review.
            </p>
          </div>

          <Card className="mb-6 border-slate-200 shadow-sm">
            <CardContent className="p-4 sm:p-5">
              <label className="relative block">
                <span className="sr-only">Search saved intelligence</span>
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="search"
                  placeholder="Search by target, category, or threat type"
                  defaultValue={filters.query}
                  onChange={(event) => debouncedSearch(event.target.value)}
                  className="h-11 w-full rounded-md border border-slate-300 bg-white pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500"
                />
              </label>

              <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
                <Select
                  label="Threat type"
                  options={threatTypeOptions}
                  value={filters.threatType}
                  onChange={(event) => updateFilter('threatType', event.target.value)}
                />
                <Select
                  label="Minimum quality"
                  options={qualityOptions}
                  value={filters.minQuality}
                  onChange={(event) => updateFilter('minQuality', event.target.value)}
                />
                <Select
                  label="Date range"
                  options={dateRangeOptions}
                  value={filters.dateRangeDays}
                  onChange={(event) => updateFilter('dateRangeDays', event.target.value)}
                />
                <Select
                  label="Sort by"
                  options={sortOptions}
                  value={filters.sortBy}
                  onChange={(event) => updateFilter('sortBy', event.target.value)}
                />
                <Select
                  label="Order"
                  options={sortOrderOptions}
                  value={filters.sortOrder}
                  onChange={(event) => updateFilter('sortOrder', event.target.value)}
                />
              </div>

              {hasActiveFilters && (
                <div className="mt-4 flex flex-col gap-3 border-t border-slate-100 pt-4 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm text-slate-600">
                    {activeFilterCount} active search {activeFilterCount === 1 ? 'constraint' : 'constraints'}
                  </span>
                  <Button variant="ghost" size="sm" onClick={clearFilters}>
                    Clear search
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {searchData && (
            <div className="mb-4 flex flex-col gap-1 text-sm text-slate-600 sm:flex-row sm:items-center sm:justify-between">
              <span>
                {totalReports === 0 ? 'No matching saved intelligence' : `Showing ${pageStart}-${pageEnd} of ${totalReports} matches`}
              </span>
              <span>
                Sorted by {sortOptions.find(option => option.value === filters.sortBy)?.label.toLowerCase()} · {filters.sortOrder}
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
                    Clear search
                  </Button>
                )}
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="space-y-4">
                {searchData?.reports.map((report) => {
                  const qualityVariant = getQualityVariant(report.quality_score);
                  const qualityLabel = getQualityLabel(report.quality_score);

                  return (
                    <Card key={report.id} className="border-slate-200 shadow-sm transition hover:border-blue-200 hover:shadow-md">
                      <CardContent className="p-5">
                        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1fr)_12rem] lg:items-start">
                          <div className="min-w-0">
                            <div className="mb-3 flex flex-wrap items-center gap-2">
                              <Badge variant={qualityVariant} size="sm" className="rounded-md">
                                {qualityLabel} · {report.quality_score.toFixed(1)}
                              </Badge>
                              {report.category && <Badge variant="default" size="sm" className="rounded-md">{report.category}</Badge>}
                              {report.threat_type && <Badge variant="default" size="sm" className="rounded-md">{report.threat_type}</Badge>}
                            </div>
                            <h2 className="truncate text-xl font-semibold text-slate-950">
                              {report.tool_name}
                            </h2>
                            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2 text-sm text-slate-500">
                              <span className="inline-flex items-center gap-1">
                                <CalendarDaysIcon className="h-4 w-4" />
                                {formatRelativeTime(report.created_at)}
                              </span>
                              <span>{formatDate(report.created_at)}</span>
                              {report.processing_time_ms ? <span>{formatProcessingTime(report.processing_time_ms)} generation</span> : null}
                            </div>
                            <p className="mt-4 line-clamp-2 max-w-3xl text-sm leading-6 text-slate-600">
                              {report.content_preview || 'No preview was saved for this report. Open it to inspect the full intelligence record.'}
                            </p>
                          </div>

                          <div className="flex flex-col gap-3 lg:items-end">
                            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 lg:text-right">
                              <div className="font-medium text-slate-900">Matched report</div>
                              <div>Open the saved record to verify sources</div>
                            </div>
                            <Link href={`/reports/${report.id}`} className="w-full lg:w-auto">
                              <Button size="sm" variant="outline" className="min-h-10 w-full gap-2 lg:w-auto">
                                <EyeIcon className="h-4 w-4" />
                                Open report
                              </Button>
                            </Link>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
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
    </AuthGuard>
  );
}
