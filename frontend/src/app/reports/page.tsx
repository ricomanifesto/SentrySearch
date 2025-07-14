/**
 * Reports Listing Page
 * 
 * Comprehensive report browser with search, filtering, and pagination.
 * Replaces Gradio's limited report viewing with professional interface.
 */

'use client';

import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  DocumentTextIcon,
  PlusIcon,
  EyeIcon,
  CalendarDaysIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, debounce } from '@/lib/utils';
import { Card, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

interface FilterState {
  query: string;
  threat_type: string;
  min_quality: string;
  sort_by: string;
  sort_order: string;
}

const sortOptions = [
  { value: 'created_at', label: 'Date Created' },
  { value: 'quality_score', label: 'Quality Score' },
  { value: 'tool_name', label: 'Tool Name' },
  { value: 'processing_time_ms', label: 'Processing Time' },
];

const sortOrderOptions = [
  { value: 'desc', label: 'Descending' },
  { value: 'asc', label: 'Ascending' },
];

const qualityOptions = [
  { value: '', label: 'Any Quality' },
  { value: '4.0', label: '4.0+ (Excellent)' },
  { value: '3.0', label: '3.0+ (Good)' },
  { value: '2.0', label: '2.0+ (Fair)' },
  { value: '1.0', label: '1.0+ (Poor)' },
];

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

  // Debounced search
  const debouncedSearch = useMemo(
    () => debounce((query: unknown) => {
      setFilters(prev => ({ ...prev, query: query as string }));
      setCurrentPage(1);
    }, 300),
    []
  );

  // Fetch reports
  const { data: reportsData, isLoading, error } = useQuery({
    queryKey: ['reports', 'list', currentPage, filters],
    queryFn: () => api.listReports(currentPage, 20, {
      query: filters.query || undefined,
      threat_type: filters.threat_type || undefined,
      min_quality: filters.min_quality ? parseFloat(filters.min_quality) : undefined,
    }),
  });

  // Fetch filter options
  const { data: filterOptions } = useQuery({
    queryKey: ['search', 'filters'],
    queryFn: () => api.getSearchFilters(),
  });

  const threatTypeOptions = useMemo(() => [
    { value: '', label: 'All Threat Types' },
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

  const hasActiveFilters = filters.query || filters.threat_type || filters.min_quality;

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="mt-2 text-gray-600">
            Browse and search your threat intelligence reports
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <Link href="/generate">
            <Button className="flex items-center space-x-2">
              <PlusIcon className="h-4 w-4" />
              <span>Generate Report</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Search and Filters */}
      <Card className="mb-8">
        <CardContent className="py-4">
          <div className="flex flex-col lg:flex-row lg:items-center space-y-4 lg:space-y-0 lg:space-x-4">
            {/* Search */}
            <div className="flex-1">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search reports..."
                  defaultValue={filters.query}
                  onChange={handleSearchChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>

            {/* Filter Toggle */}
            <Button
              variant="outline"
              onClick={() => setShowFilters(!showFilters)}
              className="lg:w-auto"
            >
              <FunnelIcon className="h-4 w-4 mr-2" />
              Filters
              {hasActiveFilters && (
                <Badge variant="info" size="sm" className="ml-2">
                  {[filters.query && 'search', filters.threat_type && 'type', filters.min_quality && 'quality'].filter(Boolean).length}
                </Badge>
              )}
            </Button>
          </div>

          {/* Expanded Filters */}
          {showFilters && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Select
                  label="Threat Type"
                  options={threatTypeOptions}
                  value={filters.threat_type}
                  onChange={(e) => handleFilterChange('threat_type', e.target.value)}
                />
                <Select
                  label="Min Quality"
                  options={qualityOptions}
                  value={filters.min_quality}
                  onChange={(e) => handleFilterChange('min_quality', e.target.value)}
                />
                <Select
                  label="Sort By"
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
                    Clear All Filters
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Results Summary */}
      {reportsData && (
        <div className="mb-6 text-sm text-gray-600">
          Showing {((reportsData.pagination.page - 1) * reportsData.pagination.limit) + 1}-{Math.min(reportsData.pagination.page * reportsData.pagination.limit, reportsData.pagination.total)} of {reportsData.pagination.total} reports
        </div>
      )}

      {/* Reports Grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <div className="animate-pulse">
                  <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2 mb-4"></div>
                  <div className="h-3 bg-gray-200 rounded w-full mb-2"></div>
                  <div className="h-3 bg-gray-200 rounded w-2/3"></div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : error ? (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="text-center py-8">
            <DocumentTextIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-red-800 mb-2">Failed to Load Reports</h3>
            <p className="text-red-600">
              There was an error loading your reports. Please try again.
            </p>
          </CardContent>
        </Card>
      ) : reportsData?.reports.length === 0 ? (
        <Card>
          <CardContent className="text-center py-12">
            <DocumentTextIcon className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              {hasActiveFilters ? 'No Reports Found' : 'No Reports Yet'}
            </h3>
            <p className="text-gray-600 mb-6 max-w-md mx-auto">
              {hasActiveFilters 
                ? 'Try adjusting your search criteria or filters to find what you\'re looking for.'
                : 'Get started by generating your first threat intelligence report.'
              }
            </p>
            <div className="space-x-4">
              {hasActiveFilters && (
                <Button variant="outline" onClick={clearFilters}>
                  Clear Filters
                </Button>
              )}
              <Link href="/generate">
                <Button>Generate First Report</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Reports Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            {reportsData?.reports.map((report) => {
              const qualityVariant = 
                report.quality_score >= 4.0 ? 'success' :
                report.quality_score >= 3.0 ? 'info' :
                report.quality_score >= 2.0 ? 'warning' : 'error';

              return (
                <Card key={report.id} className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between mb-3">
                      <h3 className="font-semibold text-gray-900 truncate flex-1 mr-2">
                        {report.tool_name}
                      </h3>
                      <Badge variant={qualityVariant} size="sm">
                        {report.quality_score.toFixed(1)}
                      </Badge>
                    </div>
                    
                    <div className="space-y-2 mb-4">
                      <div className="flex items-center text-sm text-gray-500">
                        <CalendarDaysIcon className="h-4 w-4 mr-1" />
                        <span>{formatRelativeTime(report.created_at)}</span>
                      </div>
                      
                      {report.processing_time_ms && (
                        <div className="text-sm text-gray-500">
                          Processing: {formatProcessingTime(report.processing_time_ms)}
                        </div>
                      )}
                      
                      <div className="flex items-center space-x-2">
                        {report.category && (
                          <Badge variant="default" size="sm">
                            {report.category}
                          </Badge>
                        )}
                        {report.threat_type && (
                          <Badge variant="default" size="sm">
                            {report.threat_type}
                          </Badge>
                        )}
                      </div>
                    </div>

                    {report.content_preview && (
                      <p className="text-sm text-gray-600 mb-4 line-clamp-2">
                        {report.content_preview}
                      </p>
                    )}

                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">
                        {formatDate(report.created_at)}
                      </span>
                      <Link href={`/reports/${report.id}`}>
                        <Button size="sm" variant="outline">
                          <EyeIcon className="h-4 w-4 mr-1" />
                          View
                        </Button>
                      </Link>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Pagination */}
          {reportsData && reportsData.pagination.pages > 1 && (
            <div className="flex items-center justify-between">
              <div className="flex space-x-2">
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
              
              <span className="text-sm text-gray-600">
                Page {currentPage} of {reportsData.pagination.pages}
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}