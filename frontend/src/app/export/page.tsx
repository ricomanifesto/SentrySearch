'use client';

import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ArrowDownTrayIcon,
  DocumentTextIcon,
  TableCellsIcon,
  CodeBracketIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  CalendarDaysIcon,
  FunnelIcon,
  ClipboardDocumentCheckIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, downloadAsFile } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';
import { AuthGuard } from '@/components/AuthGuard';

interface ExportConfig extends Record<string, unknown> {
  format: 'json' | 'csv' | 'markdown' | 'pdf' | 'xml';
  include_content: boolean;
  include_metadata: boolean;
  include_tags: boolean;
  date_range_days?: number;
  threat_types?: string[];
  min_quality_score?: number;
  max_reports?: number;
}

const formatOptions = [
  { value: 'json', label: 'JSON', icon: CodeBracketIcon, description: 'Structured package for downstream tooling' },
  { value: 'csv', label: 'CSV', icon: TableCellsIcon, description: 'Tabular packet for analyst review' },
  { value: 'markdown', label: 'Markdown', icon: DocumentTextIcon, description: 'Readable briefing for handoff notes' },
  { value: 'pdf', label: 'PDF', icon: DocumentTextIcon, description: 'Presentation-ready evidence packet' },
  { value: 'xml', label: 'XML', icon: CodeBracketIcon, description: 'Structured exchange for legacy systems' },
];

const dateRangeOptions = [
  { value: '', label: 'All Time' },
  { value: '7', label: 'Last 7 Days' },
  { value: '30', label: 'Last 30 Days' },
  { value: '90', label: 'Last 90 Days' },
  { value: '365', label: 'Last Year' },
];

const qualityOptions = [
  { value: '', label: 'Any Quality' },
  { value: '4.0', label: '4.0+ (Excellent)' },
  { value: '3.0', label: '3.0+ (Good)' },
  { value: '2.0', label: '2.0+ (Fair)' },
  { value: '1.0', label: '1.0+ (Poor)' },
];

export default function ExportPage() {
  const [config, setConfig] = useState<ExportConfig>({
    format: 'json',
    include_content: true,
    include_metadata: true,
    include_tags: true,
    max_reports: 1000,
  });

  const [selectedReports, setSelectedReports] = useState<string[]>([]);

  // Fetch available reports for selection
  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['reports', 'export-preview'],
    queryFn: () => api.listReports(1, 50),
  });

  // Fetch filter options
  const { data: filterOptions } = useQuery({
    queryKey: ['search', 'filters'],
    queryFn: () => api.getSearchFilters(),
  });

  // Export mutation
  const exportMutation = useMutation({
    mutationFn: (exportConfig: ExportConfig) => api.exportReports(exportConfig),
    onSuccess: (data, variables) => {
      // Download the exported file
      const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
      const filename = `sentrysearch-export-${timestamp}.${variables.format}`;
      
      let mimeType = 'application/octet-stream';
      switch (variables.format) {
        case 'json': mimeType = 'application/json'; break;
        case 'csv': mimeType = 'text/csv'; break;
        case 'markdown': mimeType = 'text/markdown'; break;
        case 'pdf': mimeType = 'application/pdf'; break;
        case 'xml': mimeType = 'application/xml'; break;
      }
      
      downloadAsFile(data, filename, mimeType);
    },
  });

  const threatTypeOptions = React.useMemo(() => [
    { value: '', label: 'All Threat Types' },
    ...(filterOptions?.threat_types?.map((type: string) => ({
      value: type,
      label: type.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())
    })) || [])
  ], [filterOptions]);

  const handleConfigChange = (key: keyof ExportConfig, value: string | boolean | string[] | number | undefined) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  const handleReportSelection = (reportId: string, selected: boolean) => {
    if (selected) {
      setSelectedReports(prev => [...prev, reportId]);
    } else {
      setSelectedReports(prev => prev.filter(id => id !== reportId));
    }
  };

  const handleSelectAll = () => {
    if (selectedReports.length === reportsData?.reports.length) {
      setSelectedReports([]);
    } else {
      setSelectedReports(reportsData?.reports.map(r => r.id) || []);
    }
  };

  const handleExport = () => {
    const exportConfig = {
      ...config,
      selected_reports: selectedReports.length > 0 ? selectedReports : undefined,
    };
    exportMutation.mutate(exportConfig);
  };

  const getFormatPreview = () => {
    const selectedFormat = formatOptions.find(f => f.value === config.format);
    return selectedFormat ? selectedFormat.description : '';
  };

  const selectedFormat = formatOptions.find(f => f.value === config.format);
  const packageScope = selectedReports.length > 0
    ? `${selectedReports.length} selected report${selectedReports.length === 1 ? '' : 's'}`
    : 'All matching reports';

  return (
    <AuthGuard>
    <div className="min-h-screen overflow-x-hidden bg-slate-50 py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <div className="mb-8 max-w-3xl">
        <Badge variant="info" size="sm">Analyst handoff</Badge>
        <h1 className="mt-3 text-3xl font-bold tracking-tight text-slate-950">
          Intelligence handoff package
        </h1>
        <p className="mt-3 text-base leading-7 text-slate-600">
          Prepare scoped report evidence for downstream review, briefings, or machine processing.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="min-w-0 lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <ArrowDownTrayIcon className="h-5 w-5" />
                <span>Package format</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <fieldset>
                <legend className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                  Package format
                </legend>
                <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                {formatOptions.map((format) => {
                  const Icon = format.icon;
                  const isSelected = config.format === format.value;
                  
                  return (
                    <label
                      key={format.value}
                      className={`block min-w-0 cursor-pointer rounded-lg border-2 p-4 text-left transition-all ${
                        isSelected
                          ? 'border-blue-600 bg-blue-50'
                          : 'border-slate-200 bg-white hover:border-slate-300'
                      }`}
                    >
                      <input
                        type="radio"
                        name="export_format"
                        value={format.value}
                        checked={config.format === format.value}
                        onChange={() => handleConfigChange('format', format.value)}
                        disabled={exportMutation.isPending}
                        className="sr-only"
                      />
                      <div className="mb-2 flex items-center space-x-3">
                        <Icon className={`h-6 w-6 flex-shrink-0 ${isSelected ? 'text-blue-700' : 'text-slate-400'}`} />
                        <span className={`font-medium ${isSelected ? 'text-blue-950' : 'text-slate-950'}`}>
                          {format.label}
                        </span>
                      </div>
                      <p className={`text-sm leading-6 ${isSelected ? 'text-blue-800' : 'text-slate-600'}`}>
                        {format.description}
                      </p>
                    </label>
                  );
                })}
                </div>
              </fieldset>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Package contents</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <h4 className="text-sm font-medium text-slate-950">Full narrative</h4>
                    <p className="text-sm leading-6 text-slate-500">Include report markdown for reviewer context.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_content}
                    onChange={(e) => handleConfigChange('include_content', e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>
                
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <h4 className="text-sm font-medium text-slate-950">Processing metadata</h4>
                    <p className="text-sm leading-6 text-slate-500">Include timestamps, quality scores, and pipeline details.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_metadata}
                    onChange={(e) => handleConfigChange('include_metadata', e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>
                
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <h4 className="text-sm font-medium text-slate-950">Source tags</h4>
                    <p className="text-sm leading-6 text-slate-500">Include search tags and categorization markers.</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_tags}
                    onChange={(e) => handleConfigChange('include_tags', e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FunnelIcon className="h-5 w-5" />
                <span>Package scope</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Select
                  label="Date Range"
                  options={dateRangeOptions}
                  value={config.date_range_days?.toString() || ''}
                  onChange={(e) => handleConfigChange('date_range_days', e.target.value ? parseInt(e.target.value) : undefined)}
                />
                
                <Select
                  label="Threat Type"
                  options={threatTypeOptions}
                  value=""
                  onChange={(e) => {
                    handleConfigChange('threat_types', e.target.value ? [e.target.value] : undefined);
                  }}
                />
                
                <Select
                  label="Minimum Quality"
                  options={qualityOptions}
                  value={config.min_quality_score?.toString() || ''}
                  onChange={(e) => handleConfigChange('min_quality_score', e.target.value ? parseFloat(e.target.value) : undefined)}
                />
                
                <Input
                  label="Max Reports"
                  type="number"
                  value={config.max_reports?.toString() || ''}
                  onChange={(e) => handleConfigChange('max_reports', e.target.value ? parseInt(e.target.value) : undefined)}
                  placeholder="No limit"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="border-b border-slate-100 pb-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Evidence queue</p>
                  <CardTitle className="mt-1 flex items-center gap-2 text-base text-slate-950">
                    <ClipboardDocumentCheckIcon className="h-5 w-5 text-slate-500" />
                    <span>Report selection</span>
                  </CardTitle>
                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    Visible reports ready for handoff review, with confidence and threat markers.
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleSelectAll}
                  className="min-h-9 self-start rounded-md border-slate-300 text-slate-800"
                >
                  {selectedReports.length === reportsData?.reports.length ? 'Clear selection' : 'Select visible'}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-3">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="h-16 bg-gray-200 rounded animate-pulse"></div>
                  ))}
                </div>
              ) : (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {reportsData?.reports.map((report) => {
                    const isSelected = selectedReports.includes(report.id);
                    const qualityVariant = 
                      report.quality_score >= 4.0 ? 'success' :
                      report.quality_score >= 3.0 ? 'info' :
                      report.quality_score >= 2.0 ? 'warning' : 'error';

                    return (
                      <div
                        key={report.id}
                        className={`flex min-w-0 cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
                          isSelected ? 'border-cyan-600 bg-cyan-50' : 'border-slate-200 bg-white hover:border-slate-300'
                        }`}
                        onClick={() => handleReportSelection(report.id, !isSelected)}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="mt-1 h-4 w-4 rounded border-slate-300 text-cyan-700 focus:ring-cyan-600"
                        />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-start justify-between gap-3">
                            <h4 className="truncate text-sm font-semibold text-slate-950">
                              {report.tool_name}
                            </h4>
                            <Badge variant={qualityVariant} size="sm">
                              Confidence {report.quality_score.toFixed(1)}
                            </Badge>
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <span className="text-xs text-slate-500">
                              {formatDate(report.created_at)}
                            </span>
                            {report.threat_type && (
                              <Badge variant="default" size="sm">
                                {report.threat_type}
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-6">
          <Card>
            <CardHeader className="border-b border-slate-100 pb-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Package manifest</p>
              <CardTitle className="mt-1 text-base text-slate-950">Handoff summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="mb-2 text-sm font-medium text-slate-950">Selected format</h4>
                  <div className="flex min-w-0 items-start gap-2">
                    <Badge variant="info">
                      {config.format.toUpperCase()}
                    </Badge>
                    <span className="min-w-0 text-sm leading-6 text-slate-600">
                      {getFormatPreview()}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="mb-2 text-sm font-medium text-slate-950">Included evidence</h4>
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      {config.include_content ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-slate-600">Full narrative</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {config.include_metadata ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-slate-600">Processing metadata</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {config.include_tags ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-slate-600">Source tags</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="mb-2 text-sm font-medium text-slate-950">Scope</h4>
                  <p className="text-sm text-slate-600">
                    {packageScope}
                  </p>
                  {config.max_reports && (
                    <p className="text-xs text-gray-500">
                      Limited to {config.max_reports} reports
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <CalendarDaysIcon className="h-5 w-5" />
                <span>Package readiness</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm text-slate-600">
                <p>
                  {selectedFormat?.label ?? config.format.toUpperCase()} package with {packageScope.toLowerCase()}.
                </p>
                <p>
                  Filters apply before packaging, with a maximum of {config.max_reports || 'all'} reports.
                </p>
                {exportMutation.error && (
                  <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                    The export package could not be prepared. Adjust the package settings and try again.
                  </div>
                )}
                {exportMutation.isPending && (
                  <div role="status" className="rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
                    Preparing export package for download.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Button
            onClick={handleExport}
            loading={exportMutation.isPending}
            disabled={exportMutation.isPending}
            className="w-full"
            size="lg"
          >
            <ArrowDownTrayIcon className="h-5 w-5 mr-2" />
            {exportMutation.isPending ? 'Preparing package...' : 'Prepare package'}
          </Button>
        </div>
      </div>
      </div>
    </div>
    </AuthGuard>
  );
}
