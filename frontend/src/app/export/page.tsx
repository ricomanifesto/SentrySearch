'use client';

import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ArrowDownTrayIcon } from '@heroicons/react/24/outline';

import { api, type Report } from '@/lib/api';
import { formatDate, downloadAsFile } from '@/lib/utils';
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

type ExportEvidenceRecord = {
  id: string;
  title: string;
  confidence: string;
  date: string;
  threatType?: string;
};

type PackageScopeControl = {
  key: 'date_range_days' | 'threat_types' | 'min_quality_score';
  label: string;
  options: Array<{ value: string; label: string }>;
  value: string;
  onChange: (value: string) => void;
};

type PackageManifestRow = { label: string; value: string; description: string };
type PackageReadinessRow = { label: string; status: string; description: string };

const formatOptions = [
  { value: 'json', label: 'JSON', description: 'Structured package for downstream tooling' },
  { value: 'csv', label: 'CSV', description: 'Tabular packet for analyst review' },
  { value: 'markdown', label: 'Markdown', description: 'Readable briefing for handoff notes' },
  { value: 'pdf', label: 'PDF', description: 'Presentation-ready evidence packet' },
  { value: 'xml', label: 'XML', description: 'Structured exchange for legacy systems' },
];

const dateRangeOptions = [
  { value: '', label: 'All time' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last year' },
];

const qualityOptions = [
  { value: '', label: 'Any quality' },
  { value: '4.0', label: '4.0+ high confidence' },
  { value: '3.0', label: '3.0+ reviewable' },
  { value: '2.0', label: '2.0+ needs review' },
  { value: '1.0', label: '1.0+ low confidence' },
];

const packageContentOptions = [
  { key: 'include_content' as const, label: 'Full narrative', description: 'Report markdown and analyst-readable context.' },
  { key: 'include_metadata' as const, label: 'Processing metadata', description: 'Timestamps, confidence scores, and pipeline details.' },
  { key: 'include_tags' as const, label: 'Source tags', description: 'Search tags and categorization markers.' },
];

const formatTaxonomyLabel = (value: string) =>
  value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

function buildExportEvidenceRecord(report: Report): ExportEvidenceRecord {
  return {
    id: report.id,
    title: report.tool_name,
    confidence: `Confidence ${report.quality_score.toFixed(1)}`,
    date: formatDate(report.created_at),
    threatType: report.threat_type ? formatTaxonomyLabel(report.threat_type) : undefined,
  };
}

const selectClass =
  'mt-1.5 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-sm text-zinc-950 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-100';

export default function ExportPage() {
  const [config, setConfig] = useState<ExportConfig>({
    format: 'json',
    include_content: true,
    include_metadata: true,
    include_tags: true,
    max_reports: 1000,
  });
  const [selectedReports, setSelectedReports] = useState<string[]>([]);

  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['reports', 'export-preview'],
    queryFn: () => api.listReports(1, 50),
  });

  const { data: filterOptions } = useQuery({
    queryKey: ['search', 'filters'],
    queryFn: () => api.getSearchFilters(),
  });

  const exportMutation = useMutation({
    mutationFn: (exportConfig: ExportConfig) => api.exportReports(exportConfig),
    onSuccess: (data, variables) => {
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
    { value: '', label: 'All threat types' },
    ...(filterOptions?.threat_types?.map((type: string) => ({ value: type, label: formatTaxonomyLabel(type) })) || []),
  ], [filterOptions]);

  const handleConfigChange = (key: keyof ExportConfig, value: string | boolean | string[] | number | undefined) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  const handleReportSelection = (reportId: string, selected: boolean) => {
    setSelectedReports((prev) => (selected ? [...prev, reportId] : prev.filter((id) => id !== reportId)));
  };

  const handleSelectAll = () => {
    if (selectedReports.length === reportsData?.reports.length) {
      setSelectedReports([]);
    } else {
      setSelectedReports(reportsData?.reports.map((r) => r.id) || []);
    }
  };

  const handleExport = () => {
    exportMutation.mutate({
      ...config,
      selected_reports: selectedReports.length > 0 ? selectedReports : undefined,
    });
  };

  const getFormatPreview = () => formatOptions.find((f) => f.value === config.format)?.description || '';

  const selectedFormat = formatOptions.find((f) => f.value === config.format);
  const packageScope = selectedReports.length > 0
    ? `${selectedReports.length} selected report${selectedReports.length === 1 ? '' : 's'}`
    : 'All matching reports';
  const includedEvidenceLabels = packageContentOptions.filter((option) => Boolean(config[option.key])).map((option) => option.label);
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
    { label: 'File type', value: config.format.toUpperCase(), description: getFormatPreview() },
    {
      label: 'Included evidence',
      value: `${includedEvidenceLabels.length} evidence layer${includedEvidenceLabels.length === 1 ? '' : 's'}`,
      description: includedEvidenceLabels.length > 0 ? includedEvidenceLabels.join(', ') : 'No evidence layers selected for this handoff.',
    },
    {
      label: 'Scope boundary',
      value: packageScope,
      description: config.max_reports ? `Capped at ${config.max_reports} records before packaging.` : 'No record cap applied before packaging.',
    },
  ];
  const packageReadinessRows: PackageReadinessRow[] = [
    { label: 'File package', status: selectedFormat?.label ?? config.format.toUpperCase(), description: `${getFormatPreview()} ready for download when generated.` },
    {
      label: 'Evidence queue',
      status: selectedReports.length > 0 ? `${selectedReports.length} selected` : 'All matching',
      description: selectedReports.length > 0 ? 'Only selected report records will be packaged.' : 'The current scope will package every matching report record.',
    },
    {
      label: 'Scope constraints',
      status: config.max_reports ? `${config.max_reports} record cap` : 'No record cap',
      description: 'Review window, threat family, and confidence constraints apply before packaging.',
    },
  ];

  return (
    <AuthGuard>
      <main data-surface="export-handoff" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">Analyst handoff</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Intelligence handoff package</h1>
            <p className="mt-4 text-lg leading-8 text-zinc-600">
              Prepare scoped report evidence for downstream review, briefings, or
              machine processing.
            </p>
          </div>

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="min-w-0 space-y-6 lg:col-span-2">
              <section className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Package format</h2>
                <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {formatOptions.map((format) => {
                    const isSelected = config.format === format.value;
                    return (
                      <label
                        key={format.value}
                        className={`block min-w-0 cursor-pointer rounded-lg border p-4 text-left transition-colors ${
                          isSelected ? 'border-blue-600 bg-blue-50' : 'border-zinc-200 bg-white hover:border-zinc-300'
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
                        <span className={`block text-sm font-medium ${isSelected ? 'text-blue-900' : 'text-zinc-950'}`}>{format.label}</span>
                        <span className={`mt-1 block text-sm leading-6 ${isSelected ? 'text-blue-800' : 'text-zinc-600'}`}>{format.description}</span>
                      </label>
                    );
                  })}
                </div>
              </section>

              <section className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Package contents</h2>
                <div className="mt-4 space-y-3">
                  {packageContentOptions.map((option) => (
                    <label
                      key={option.key}
                      className={`flex min-w-0 cursor-pointer items-start justify-between gap-4 rounded-lg border p-4 transition-colors ${
                        config[option.key] ? 'border-blue-200 bg-blue-50' : 'border-zinc-200 bg-white hover:border-zinc-300'
                      }`}
                    >
                      <span className="min-w-0">
                        <span className="block text-sm font-medium text-zinc-950">{option.label}</span>
                        <span className="mt-1 block text-sm leading-6 text-zinc-500">{option.description}</span>
                      </span>
                      <input
                        type="checkbox"
                        checked={Boolean(config[option.key])}
                        onChange={(e) => handleConfigChange(option.key, e.target.checked)}
                        className="mt-1 h-4 w-4 shrink-0 rounded border-zinc-300 text-blue-600 focus:ring-blue-500"
                      />
                    </label>
                  ))}
                </div>
              </section>

              <section data-contract="Export.PackageScopeControls.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Handoff constraints</h2>
                <p className="mt-1 text-sm leading-6 text-zinc-500">
                  Constrain the package to the evidence window, threat family, and confidence floor needed for review.
                </p>
                <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
                  {packageScopeControls.map((control) => (
                    <label key={control.key} className="block">
                      <span className="block text-sm font-medium text-zinc-800">{control.label}</span>
                      <select value={control.value} onChange={(event) => control.onChange(event.target.value)} className={selectClass}>
                        {control.options.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </label>
                  ))}
                  <label className="block">
                    <span className="block text-sm font-medium text-zinc-800">Maximum records</span>
                    <input
                      type="number"
                      value={config.max_reports?.toString() || ''}
                      onChange={(e) => handleConfigChange('max_reports', e.target.value ? parseInt(e.target.value) : undefined)}
                      placeholder="No limit"
                      className={selectClass}
                    />
                  </label>
                </div>
              </section>

              <section className="rounded-xl border border-zinc-200 bg-white p-5">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <h2 className="text-base font-semibold text-zinc-950">Report selection</h2>
                    <p className="mt-1 text-sm leading-6 text-zinc-500">
                      Visible reports ready for handoff review, with confidence and threat markers.
                    </p>
                  </div>
                  <button type="button" onClick={handleSelectAll} className="inline-flex h-9 shrink-0 items-center justify-center rounded-lg border border-zinc-300 bg-white px-3 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50">
                    {selectedReports.length === reportsData?.reports.length ? 'Clear selection' : 'Select visible'}
                  </button>
                </div>
                <div className="mt-4">
                  {isLoading ? (
                    <div className="space-y-3">
                      {[...Array(5)].map((_, i) => (
                        <div key={i} className="h-16 animate-pulse rounded-lg bg-zinc-100" />
                      ))}
                    </div>
                  ) : (
                    <div className="max-h-96 space-y-3 overflow-y-auto">
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
                </div>
              </section>
            </div>

            <div className="min-w-0 space-y-6">
              <section data-contract="Export.PackageManifest.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Handoff summary</h2>
                <div className="mt-4 space-y-3">
                  {packageManifestRows.map((row) => (
                    <div key={row.label}>
                      <div className="flex min-w-0 items-center justify-between gap-3">
                        <span className="text-sm text-zinc-500">{row.label}</span>
                        <span className="rounded-md bg-blue-50 px-2 py-0.5 text-sm font-medium text-blue-700">{row.value}</span>
                      </div>
                      <p className="mt-1 text-sm leading-6 text-zinc-600">{row.description}</p>
                    </div>
                  ))}
                </div>
              </section>

              <section data-contract="Export.PackageReadiness.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Package readiness</h2>
                <div className="mt-4 space-y-3">
                  {packageReadinessRows.map((row) => (
                    <div key={row.label}>
                      <div className="flex min-w-0 items-center justify-between gap-3">
                        <span className="text-sm font-medium text-zinc-950">{row.label}</span>
                        <span className="rounded-md bg-zinc-100 px-2 py-0.5 text-sm font-medium text-zinc-700">{row.status}</span>
                      </div>
                      <p className="mt-1 text-sm leading-6 text-zinc-500">{row.description}</p>
                    </div>
                  ))}
                  {exportMutation.error && (
                    <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                      The export package could not be prepared. Adjust the package settings and try again.
                    </div>
                  )}
                  {exportMutation.isPending && (
                    <div role="status" className="rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
                      Preparing export package for download.
                    </div>
                  )}
                </div>
              </section>

              <button
                type="button"
                onClick={handleExport}
                disabled={exportMutation.isPending}
                className="flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-base font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
              >
                <ArrowDownTrayIcon className="h-5 w-5" aria-hidden="true" />
                {exportMutation.isPending ? 'Preparing package…' : 'Prepare package'}
              </button>
            </div>
          </div>
        </div>
      </main>
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
      className={`flex min-w-0 cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
        isSelected ? 'border-blue-600 bg-blue-50' : 'border-zinc-200 bg-white hover:border-zinc-300'
      }`}
    >
      <input
        type="checkbox"
        checked={isSelected}
        onChange={(event) => onSelectionChange(record.id, event.target.checked)}
        className="mt-1 h-4 w-4 shrink-0 rounded border-zinc-300 text-blue-600 focus:ring-blue-500"
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-start justify-between gap-3">
          <span className="truncate text-sm font-medium text-zinc-950">{record.title}</span>
          <span className="shrink-0 rounded-md bg-blue-50 px-2 py-0.5 text-sm font-medium text-blue-700">{record.confidence}</span>
        </span>
        <span className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-sm text-zinc-500">{record.date}</span>
          {record.threatType ? (
            <span className="rounded-md bg-zinc-100 px-2 py-0.5 text-sm text-zinc-700">{record.threatType}</span>
          ) : null}
        </span>
      </span>
    </label>
  );
}
