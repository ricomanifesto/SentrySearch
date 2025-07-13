/**
 * Advanced Export Interface
 * 
 * Bulk export functionality for threat intelligence reports with 
 * multiple formats and filtering options.
 */

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
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, downloadAsFile } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

interface ExportConfig {
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
  { value: 'json', label: 'JSON', icon: CodeBracketIcon, description: 'Machine-readable format for APIs' },
  { value: 'csv', label: 'CSV', icon: TableCellsIcon, description: 'Spreadsheet format for analysis' },
  { value: 'markdown', label: 'Markdown', icon: DocumentTextIcon, description: 'Human-readable documentation' },
  { value: 'pdf', label: 'PDF', icon: DocumentTextIcon, description: 'Print-ready reports' },
  { value: 'xml', label: 'XML', icon: CodeBracketIcon, description: 'Structured data exchange' },
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

  const handleConfigChange = (key: keyof ExportConfig, value: any) => {
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
    const selectedFormat = formatOptions.find(f => f.format === config.format);
    return selectedFormat ? selectedFormat.description : '';
  };

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Export Reports</h1>
        <p className="mt-2 text-gray-600">
          Bulk export threat intelligence reports in multiple formats
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Export Configuration */}
        <div className="lg:col-span-2 space-y-6">
          {/* Format Selection */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <ArrowDownTrayIcon className="h-5 w-5" />
                <span>Export Format</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {formatOptions.map((format) => {
                  const Icon = format.icon;
                  const isSelected = config.format === format.value;
                  
                  return (
                    <button
                      key={format.value}
                      onClick={() => handleConfigChange('format', format.value)}
                      className={`p-4 border-2 rounded-lg transition-all text-left ${
                        isSelected
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-center space-x-3 mb-2">
                        <Icon className={`h-6 w-6 ${isSelected ? 'text-blue-600' : 'text-gray-400'}`} />
                        <span className={`font-medium ${isSelected ? 'text-blue-900' : 'text-gray-900'}`}>
                          {format.label}
                        </span>
                      </div>
                      <p className={`text-sm ${isSelected ? 'text-blue-700' : 'text-gray-600'}`}>
                        {format.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Content Options */}
          <Card>
            <CardHeader>
              <CardTitle>Content Options</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Include Full Content</h4>
                    <p className="text-sm text-gray-500">Export complete report markdown content</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_content}
                    onChange={(e) => handleConfigChange('include_content', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Include Metadata</h4>
                    <p className="text-sm text-gray-500">Export timestamps, quality scores, and processing info</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_metadata}
                    onChange={(e) => handleConfigChange('include_metadata', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900">Include Tags</h4>
                    <p className="text-sm text-gray-500">Export search tags and categorization data</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.include_tags}
                    onChange={(e) => handleConfigChange('include_tags', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Filters */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FunnelIcon className="h-5 w-5" />
                <span>Export Filters</span>
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
                    // Handle multiple threat types (simplified for demo)
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

          {/* Report Selection */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Select Reports</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleSelectAll}
                >
                  {selectedReports.length === reportsData?.reports.length ? 'Deselect All' : 'Select All'}
                </Button>
              </CardTitle>
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
                        className={`flex items-center space-x-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                          isSelected ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
                        }`}
                        onClick={() => handleReportSelection(report.id, !isSelected)}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <h4 className="text-sm font-medium text-gray-900 truncate">
                              {report.tool_name}
                            </h4>
                            <Badge variant={qualityVariant} size="sm">
                              {report.quality_score.toFixed(1)}
                            </Badge>
                          </div>
                          <div className="flex items-center space-x-4 mt-1">
                            <span className="text-xs text-gray-500">
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

        {/* Export Summary */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Export Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Format</h4>
                  <div className="flex items-center space-x-2">
                    <Badge variant="info">
                      {config.format.toUpperCase()}
                    </Badge>
                    <span className="text-sm text-gray-600">
                      {getFormatPreview()}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Content</h4>
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      {config.include_content ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-gray-600">Full Content</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {config.include_metadata ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-gray-600">Metadata</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      {config.include_tags ? (
                        <CheckCircleIcon className="h-4 w-4 text-green-600" />
                      ) : (
                        <ExclamationTriangleIcon className="h-4 w-4 text-gray-400" />
                      )}
                      <span className="text-sm text-gray-600">Tags</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Selection</h4>
                  <p className="text-sm text-gray-600">
                    {selectedReports.length > 0 
                      ? `${selectedReports.length} reports selected`
                      : 'All matching reports'
                    }
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
                <span>Recent Exports</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="text-center py-4 text-gray-500">
                  <p className="text-sm">No recent exports</p>
                </div>
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
            {exportMutation.isPending ? 'Exporting...' : 'Export Reports'}
          </Button>
        </div>
      </div>
    </div>
  );
}