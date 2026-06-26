'use client';

import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  CalendarDaysIcon,
  DocumentTextIcon,
  EyeIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  PlusIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { debounce, formatDate, formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardContent } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { SurfaceHeader } from '@/components/ui/SurfaceHeader';

interface FilterState {
  query: string;
  threat_type: string;
  min_quality: string;
  sort_by: string;
  sort_order: string;
}

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
  { value: '4.0', label: '4.0+ excellent' },
  { value: '3.0', label: '3.0+ good' },
  { value: '2.0', label: '2.0+ needs review' },
  { value: '1.0', label: '1.0+ low confidence' },
];

const getQualityVariant = (score: number) =>
  score >= 4.0 ? 'success' : score >= 3.0 ? 'info' : score >= 2.0 ? 'warning' : 'error';

const getQualityLabel = (score: number) =>
  score >= 4.0 ? 'High confidence' : score >= 3.0 ? 'Reviewable' : score >= 2.0 ? 'Needs review' : 'Low confidence';

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
      setFilters(prev => ({ ...prev, query: query as string }));
      setCurrentPage(1);
    }, 300),
    []
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
    ...(filterOptions?.threat_types.map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    })) || [])
  ], [filterOptions]);

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setCurrentPage(1);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    debouncedSearch(e.target.value);
  };

  const clearFilters = () => {
    setFilters({
      query: '',
      threat_type: '',
      min_quality: '',
      sort_by: 'created_at',
      sort_order: 'desc',
    });
    setCurrentPage(1);
  };

  const hasActiveFilters = Boolean(filters.query || filters.threat_type || filters.min_quality);
  const activeFilterCount = [filters.query, filters.threat_type, filters.min_quality].filter(Boolean).length;
  const totalReports = reportsData?.pagination.total ?? 0;
  const pageStart = reportsData ? ((reportsData.pagination.page - 1) * reportsData.pagination.limit) + 1 : 0;
  const pageEnd = reportsData ? Math.min(reportsData.pagination.page * reportsData.pagination.limit, reportsData.pagination.total) : 0;

  return (
    <AuthGuard>
      <div data-surface="report-review-queue" className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <SurfaceHeader
            eyebrow="Saved intelligence"
            title="Review queue for saved intelligence"
            description="Search saved threat profiles, compare analyst confidence, and reopen each intelligence record with its source-backed context."
            action={(
              <Link href="/generate" className="block w-full sm:w-auto">
                <Button className="min-h-11 w-full gap-2 sm:w-auto">
                  <PlusIcon className="h-4 w-4" />
                  Generate report
                </Button>
              </Link>
            )}
          />

          <Card className="mb-6 border-slate-200 shadow-sm">
            <CardContent className="py-4">
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
                <label className="relative block">
                  <span className="sr-only">Search reports</span>
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  <input
                    type="search"
                    placeholder="Search by target, category, or threat type"
                    defaultValue={filters.query}
                    onChange={handleSearchChange}
                    className="h-11 w-full rounded-md border border-slate-300 bg-white pl-10 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500"
                  />
                </label>

                <Button
                  variant="outline"
                  onClick={() => setShowFilters(!showFilters)}
                  className="min-h-11 w-full gap-2 lg:w-auto"
                  aria-expanded={showFilters}
                >
                  <FunnelIcon className="h-4 w-4" />
                  Filters
                  {hasActiveFilters && (
                    <Badge variant="info" size="sm" className="rounded-md">
                      {activeFilterCount}
                    </Badge>
                  )}
                </Button>
              </div>

              {showFilters && (
                <div className="mt-4 border-t border-slate-100 pt-4">
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
                    <Select
                      label="Threat type"
                      options={threatTypeOptions}
                      value={filters.threat_type}
                      onChange={(e) => handleFilterChange('threat_type', e.target.value)}
                    />
                    <Select
                      label="Minimum quality"
                      options={qualityOptions}
                      value={filters.min_quality}
                      onChange={(e) => handleFilterChange('min_quality', e.target.value)}
                    />
                    <Select
                      label="Sort by"
                      options={sortOptions}
                      value={filters.sort_by}
                      onChange={(e) => handleFilterChange('sort_by', e.target.value)}
                    />
                    <Select
                      label="Order"
                      options={sortOrderOptions}
                      value={filters.sort_order}
                      onChange={(e) => handleFilterChange('sort_order', e.target.value)}
                    />
                  </div>
                  {hasActiveFilters && (
                    <div className="mt-4">
                      <Button variant="ghost" size="sm" onClick={clearFilters}>
                        Clear filters
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {reportsData && (
            <div className="mb-4 grid gap-3 rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600 shadow-sm lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
              <span className="space-y-1">
                <span className="block">
                  <span className="font-semibold text-slate-950">Review queue:</span>{' '}
                  {totalReports === 0 ? 'no saved reports' : `showing ${pageStart}-${pageEnd} of ${totalReports} saved reports`}
                </span>
                <span className="block text-xs text-slate-500">
                  Sorted by {sortOptions.find(option => option.value === filters.sort_by)?.label.toLowerCase()} · {filters.sort_order}
                </span>
              </span>
              <span className="inline-flex items-start gap-2 rounded-md bg-slate-50 px-3 py-2 leading-5 text-slate-700">
                <ShieldCheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-700" />
                Provenance posture: open records to inspect source context, tags, and narrative when available
              </span>
            </div>
          )}

          {isLoading ? (
            <div className="space-y-4" role="status" aria-label="Loading reports">
              {[...Array(4)].map((_, i) => (
                <Card key={i} className="border-slate-200">
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
                <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-red-400" />
                <h3 className="mb-2 text-lg font-semibold text-red-900">Reports could not be loaded</h3>
                <p className="mx-auto max-w-md text-sm leading-6 text-red-700">
                  The saved report list is unavailable. Retry from this page or generate a new report if the issue persists.
                </p>
              </CardContent>
            </Card>
          ) : reportsData?.reports.length === 0 ? (
            <Card className="border-slate-200">
              <CardContent className="py-12 text-center">
                <DocumentTextIcon className="mx-auto mb-4 h-16 w-16 text-slate-400" />
                <h3 className="mb-2 text-lg font-semibold text-slate-950">
                  {hasActiveFilters ? 'No matching reports' : 'No saved reports yet'}
                </h3>
                <p className="mx-auto mb-6 max-w-md text-sm leading-6 text-slate-600">
                  {hasActiveFilters
                    ? 'Adjust the search or filters to broaden the review queue.'
                    : 'Generate the first threat intelligence report to start building the saved review queue.'}
                </p>
                <div className="flex flex-col justify-center gap-3 sm:flex-row">
                  {hasActiveFilters && (
                    <Button variant="outline" onClick={clearFilters}>
                      Clear filters
                    </Button>
                  )}
                  <Link href="/generate">
                    <Button>Generate report</Button>
                  </Link>
                </div>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="space-y-4">
                {reportsData?.reports.map((report) => {
                  const qualityVariant = getQualityVariant(report.quality_score);
                  const qualityLabel = getQualityLabel(report.quality_score);

                  return (
                    <Card
                      key={report.id}
                      data-contract="Card.ReportReviewRecord.v1"
                      className="border-slate-200 shadow-sm transition hover:border-blue-200 hover:shadow-md"
                    >
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
                            <div className="mt-3 grid gap-3 sm:grid-cols-2">
                              <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                                  Analyst confidence
                                </div>
                                <div className="mt-1 text-sm font-medium text-slate-950">
                                  {qualityLabel} · {report.quality_score.toFixed(1)}
                                </div>
                              </div>
                              <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                                  Provenance posture
                                </div>
                                <div className="mt-1 text-sm font-medium text-slate-950">
                                  Detail review available
                                </div>
                              </div>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2 text-sm text-slate-500">
                              <span className="inline-flex items-center gap-1">
                                <CalendarDaysIcon className="h-4 w-4" />
                                {formatRelativeTime(report.created_at)}
                              </span>
                              <span>{formatDate(report.created_at)}</span>
                              {report.processing_time_ms ? <span>{formatProcessingTime(report.processing_time_ms)} generation</span> : null}
                            </div>
                            <p className="mt-4 line-clamp-2 max-w-3xl text-sm leading-6 text-slate-600">
                              {report.content_preview || 'No preview was saved for this report. Open it to review the full intelligence record.'}
                            </p>
                          </div>

                          <div className="flex flex-col gap-3 lg:items-end">
                            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 lg:text-right">
                              <div className="font-medium text-slate-900">Review record</div>
                              <div>Report body and available context</div>
                            </div>
                            <Link href={`/reports/${report.id}`} className="w-full lg:w-auto">
                              <Button size="sm" variant="outline" className="min-h-10 w-full gap-2 lg:w-auto">
                                <EyeIcon className="h-4 w-4" />
                                Open intelligence record
                              </Button>
                            </Link>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              {reportsData && reportsData.pagination.pages > 1 && (
                <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <span className="text-sm text-slate-600">
                    Page {currentPage} of {reportsData.pagination.pages}
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
                      disabled={currentPage >= reportsData.pagination.pages}
                      onClick={() => setCurrentPage(prev => Math.min(reportsData.pagination.pages, prev + 1))}
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
