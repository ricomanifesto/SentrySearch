'use client';

import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ArrowDownTrayIcon,
  DocumentTextIcon,
  TableCellsIcon,
  CodeBracketIcon,
  CalendarDaysIcon,
  FunnelIcon,
  ClipboardDocumentCheckIcon,
} from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import { formatDate, downloadAsFile } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';
import { AuthGuard } from '@/components/AuthGuard';
import { SurfaceHeader } from '@/components/ui/SurfaceHeader';

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

type ExportEvidenceRecord = {
  id: string;
  title: string;
  confidence: string;
  date: string;
  threatType?: string;
  qualityVariant: 'default' | 'success' | 'warning' | 'error' | 'info';
};

type PackageScopeControl = {
  key: 'date_range_days' | 'threat_types' | 'min_quality_score';
  label: string;
  options: Array<{ value: string; label: string }>;
  value: string;
  onChange: (value: string) => void;
};

type PackageManifestRow = {
  label: string;
  value: string;
  description: string;
};

type PackageReadinessRow = {
  label: string;
  status: string;
  description: string;
  variant: 'default' | 'success' | 'warning' | 'error' | 'info';
};

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

const packageContentOptions = [
  {
    key: 'include_content' as const,
    label: 'Full narrative',
    description: 'Report markdown and analyst-readable context.',
  },
  {
    key: 'include_metadata' as const,
    label: 'Processing metadata',
    description: 'Timestamps, confidence scores, and pipeline details.',
  },
  {
    key: 'include_tags' as const,
    label: 'Source tags',
    description: 'Search tags and categorization markers.',
  },
];

const getQualityVariant = (score: number): ExportEvidenceRecord['qualityVariant'] =>
  score >= 4.0 ? 'success' : score >= 3.0 ? 'info' : score >= 2.0 ? 'warning' : 'error';

const formatTaxonomyLabel = (value: string) =>
  value.replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());

function buildExportEvidenceRecord(report: Report): ExportEvidenceRecord {
  return {
    id: report.id,
    title: report.tool_name,
    confidence: `Confidence ${report.quality_score.toFixed(1)}`,
    date: formatDate(report.created_at),
    threatType: report.threat_type ? formatTaxonomyLabel(report.threat_type) : undefined,
    qualityVariant: getQualityVariant(report.quality_score),
  };
}

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
  const includedEvidenceLabels = packageContentOptions
    .filter((option) => Boolean(config[option.key]))
    .map((option) => option.label);
  const packageScopeControls: PackageScopeControl[] = [
    {
      key: 'date_range_days',
      label: 'Review window',
      options: dateRangeOptions,
      value: config.date_range_days?.toString() || '',
      onChange: (value) => handleConfigChange('date_range_days', value ? parseInt(value) : undefined),
    },
    {
      key: 'threat_types',
      label: 'Threat family',
      options: threatTypeOptions,
      value: config.threat_types?.[0] || '',
      onChange: (value) => handleConfigChange('threat_types', value ? [value] : undefined),
    },
    {
      key: 'min_quality_score',
      label: 'Minimum confidence',
      options: qualityOptions,
      value: config.min_quality_score?.toString() || '',
      onChange: (value) => handleConfigChange('min_quality_score', value ? parseFloat(value) : undefined),
    },
  ];
  const packageManifestRows: PackageManifestRow[] = [
    {
      label: 'File type',
      value: config.format.toUpperCase(),
      description: getFormatPreview(),
    },
    {
      label: 'Included evidence',
      value: `${includedEvidenceLabels.length} evidence layer${includedEvidenceLabels.length === 1 ? '' : 's'}`,
      description: includedEvidenceLabels.length > 0
        ? includedEvidenceLabels.join(', ')
        : 'No evidence layers selected for this handoff.',
    },
    {
      label: 'Scope boundary',
      value: packageScope,
      description: config.max_reports
        ? `Capped at ${config.max_reports} records before packaging.`
        : 'No record cap applied before packaging.',
    },
  ];
  const packageReadinessRows: PackageReadinessRow[] = [
    {
      label: 'File package',
      status: selectedFormat?.label ?? config.format.toUpperCase(),
      description: `${getFormatPreview()} ready for download when generated.`,
      variant: 'info',
    },
    {
      label: 'Evidence queue',
      status: selectedReports.length > 0 ? `${selectedReports.length} selected` : 'All matching',
      description: selectedReports.length > 0
        ? 'Only selected report records will be packaged.'
        : 'The current scope will package every matching report record.',
      variant: selectedReports.length > 0 ? 'success' : 'default',
    },
    {
      label: 'Scope constraints',
      status: config.max_reports ? `${config.max_reports} record cap` : 'No record cap',
      description: 'Review window, threat family, and confidence constraints apply before packaging.',
      variant: config.max_reports ? 'warning' : 'default',
    },
  ];

  return (
    <AuthGuard>
    <div className="min-h-screen overflow-x-hidden bg-slate-50 py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      <SurfaceHeader
        eyebrow="Analyst handoff"
        title="Intelligence handoff package"
        description="Prepare scoped report evidence for downstream review, briefings, or machine processing."
      />

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
                {packageContentOptions.map((option) => (
                  <label
                    key={option.key}
                    className={`flex min-w-0 cursor-pointer items-start justify-between gap-4 rounded-md border p-4 transition ${
                      config[option.key]
                        ? 'border-cyan-200 bg-cyan-50'
                        : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <span className="min-w-0">
                      <span className="block text-sm font-medium text-slate-950">{option.label}</span>
                      <span className="mt-1 block text-sm leading-6 text-slate-500">{option.description}</span>
                    </span>
                    <input
                      type="checkbox"
                      checked={Boolean(config[option.key])}
                      onChange={(e) => handleConfigChange(option.key, e.target.checked)}
                      className="mt-1 h-4 w-4 shrink-0 rounded border-slate-300 text-cyan-700 focus:ring-cyan-600"
                    />
                  </label>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card data-contract="Export.PackageScopeControls.v1">
            <CardHeader className="border-b border-slate-100 pb-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Package scope</p>
              <CardTitle className="mt-1 flex items-center space-x-2">
                <FunnelIcon className="h-5 w-5 text-slate-500" />
                <span>Handoff constraints</span>
              </CardTitle>
              <p className="mt-2 text-sm leading-6 text-slate-500">
                Constrain the package to the evidence window, threat family, and confidence floor needed for review.
              </p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {packageScopeControls.map((control) => (
                  <Select
                    key={control.key}
                    label={control.label}
                    options={control.options}
                    value={control.value}
                    onChange={(event) => control.onChange(event.target.value)}
                  />
                ))}
                <Input
                  label="Maximum records"
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
                  {reportsData?.reports.map((report) => (
                    <ExportEvidenceQueueRecord
                      key={report.id}
                      record={buildExportEvidenceRecord(report)}
                      isSelected={selectedReports.includes(report.id)}
                      onSelectionChange={handleReportSelection}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-6">
          <Card data-contract="Export.PackageManifest.v1">
            <CardHeader className="border-b border-slate-100 pb-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Package manifest</p>
              <CardTitle className="mt-1 text-base text-slate-950">Handoff summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {packageManifestRows.map((row) => (
                  <div key={row.label} className="rounded-md border border-slate-200 bg-white p-3">
                    <div className="flex min-w-0 items-start justify-between gap-3">
                      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        {row.label}
                      </span>
                      <Badge variant="info" size="sm" className="shrink-0 rounded-md">
                        {row.value}
                      </Badge>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      {row.description}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card data-contract="Export.PackageReadiness.v1">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <CalendarDaysIcon className="h-5 w-5" />
                <span>Package readiness</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm text-slate-600">
                {packageReadinessRows.map((row) => (
                  <div key={row.label} className="rounded-md border border-slate-200 bg-white p-3">
                    <div className="flex min-w-0 items-start justify-between gap-3">
                      <span className="font-medium text-slate-950">{row.label}</span>
                      <Badge variant={row.variant} size="sm" className="shrink-0 rounded-md">
                        {row.status}
                      </Badge>
                    </div>
                    <p className="mt-2 leading-6 text-slate-600">
                      {row.description}
                    </p>
                  </div>
                ))}
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

function ExportEvidenceQueueRecord({
  record,
  isSelected,
  onSelectionChange,
}: {
  record: ExportEvidenceRecord;
  isSelected: boolean;
  onSelectionChange: (reportId: string, selected: boolean) => void;
}) {
  return (
    <label
      data-contract="Export.EvidenceQueueRecord.v1"
      className={`flex min-w-0 cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
        isSelected ? 'border-cyan-600 bg-cyan-50' : 'border-slate-200 bg-white hover:border-slate-300'
      }`}
    >
      <input
        type="checkbox"
        checked={isSelected}
        onChange={(event) => onSelectionChange(record.id, event.target.checked)}
        className="mt-1 h-4 w-4 shrink-0 rounded border-slate-300 text-cyan-700 focus:ring-cyan-600"
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-start justify-between gap-3">
          <span className="truncate text-sm font-semibold text-slate-950">
            {record.title}
          </span>
          <Badge variant={record.qualityVariant} size="sm" className="shrink-0 rounded-md">
            {record.confidence}
          </Badge>
        </span>
        <span className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500">
            {record.date}
          </span>
          {record.threatType ? (
            <Badge variant="default" size="sm" className="rounded-md">
              {record.threatType}
            </Badge>
          ) : null}
        </span>
      </span>
    </label>
  );
}
