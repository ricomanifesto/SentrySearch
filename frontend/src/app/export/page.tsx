'use client';

import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ArrowDownTrayIcon } from '@heroicons/react/24/outline';

import { api, type AnalystDisposition, type ExportConfig, type Report, type ReviewStatus } from '@/lib/api';
import {
  dateRangeFilterOptions,
  formatTaxonomyLabel,
  qualityFilterOptions,
} from '@/lib/report-query';
import { formatDate, downloadAsFile } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { getReviewStatusClasses, getReviewStatusLabel } from '@/lib/report-status';
import { getAnalystDispositionClasses, getAnalystDispositionLabel } from '@/lib/analyst-disposition';
import { getExportScopeState } from '@/lib/export-readiness';

type ExportEvidenceRecord = {
  id: string;
  title: string;
  quality: string;
  date: string;
  threatType?: string;
  reviewStatus: ReviewStatus;
  analystDisposition: AnalystDisposition;
};

type PackageScopeControl = {
  key: 'review_statuses' | 'analyst_dispositions' | 'date_range_days' | 'threat_types' | 'min_quality_score';
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
  { value: 'xml', label: 'XML', description: 'Structured exchange for legacy systems' },
];

const packageContentOptions = [
  { key: 'include_content' as const, label: 'Full narrative', description: 'Report markdown and analyst-readable context.' },
  { key: 'include_metadata' as const, label: 'Processing metadata', description: 'Timestamps, content-quality scores, lifecycle states, analyst judgments, and route details.' },
  { key: 'include_sources' as const, label: 'Source evidence', description: 'Canonical source records with URLs, access dates, and key findings.' },
  { key: 'include_tags' as const, label: 'Search context', description: 'Search tags and categorization markers.' },
];

const scopeConfigKeys: Array<keyof ExportConfig> = [
  'review_statuses',
  'analyst_dispositions',
  'date_range_days',
  'threat_types',
  'min_quality_score',
  'max_reports',
];

const handoffStateOptions = [
  { value: 'evaluated', label: 'Evaluated reports' },
  { value: 'reviewable', label: 'Reviewable only' },
  { value: 'needs_attention', label: 'Needs attention' },
  { value: 'needs_evaluation', label: 'Needs evaluation' },
  { value: 'generation_failed', label: 'Generation failures' },
  { value: 'all', label: 'All lifecycle states' },
];

const analystDispositionOptions = [
  { value: 'accepted', label: 'Accepted for reuse' },
  { value: 'unreviewed', label: 'Awaiting analyst judgment' },
  { value: 'needs_revision', label: 'Needs revision' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'all', label: 'All analyst dispositions' },
];

function reviewStatusesForHandoff(value: string): ReviewStatus[] | undefined {
  if (value === 'evaluated') return ['reviewable', 'needs_attention'];
  if (value === 'all') return undefined;
  return [value as ReviewStatus];
}

function handoffValueForReviewStatuses(statuses?: ReviewStatus[]): string {
  if (!statuses) return 'all';
  if (statuses.join(',') === 'reviewable,needs_attention') return 'evaluated';
  return statuses[0] ?? 'all';
}

function dispositionsForHandoff(value: string): AnalystDisposition[] | undefined {
  return value === 'all' ? undefined : [value as AnalystDisposition];
}

function handoffValueForDispositions(dispositions?: AnalystDisposition[]): string {
  return dispositions?.[0] ?? 'all';
}

function buildExportEvidenceRecord(report: Report): ExportEvidenceRecord {
  return {
    id: report.id,
    title: report.tool_name,
    quality: report.quality_score == null
      ? 'Content quality not scored'
      : `Content quality ${report.quality_score.toFixed(2)}`,
    date: formatDate(report.created_at),
    threatType: report.threat_type ? formatTaxonomyLabel(report.threat_type) : undefined,
    reviewStatus: report.review_status,
    analystDisposition: report.analyst_disposition,
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
    include_sources: true,
    max_reports: 1000,
    review_statuses: ['reviewable', 'needs_attention'],
    analyst_dispositions: ['accepted'],
  });
  const [selectedReports, setSelectedReports] = useState<string[]>([]);

  const { data: reportsData, isLoading, error: reportsError } = useQuery({
    queryKey: [
      'reports',
      'export-preview',
      config.review_statuses,
      config.analyst_dispositions,
      config.date_range_days,
      config.threat_types,
      config.min_quality_score,
    ],
    queryFn: () => api.searchReports({
      review_statuses: config.review_statuses,
      analyst_dispositions: config.analyst_dispositions,
      date_range_days: config.date_range_days,
      threat_types: config.threat_types,
      min_quality_score: config.min_quality_score,
    }, 1, 50),
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
    if (scopeConfigKeys.includes(key)) {
      setSelectedReports([]);
    }
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
    if (!exportScope.canPrepare) return;
    exportMutation.mutate({
      ...config,
      selected_reports: selectedReports.length > 0 ? selectedReports : undefined,
    });
  };

  const getFormatPreview = () => formatOptions.find((f) => f.value === config.format)?.description || '';

  const selectedFormat = formatOptions.find((f) => f.value === config.format);
  const exportScope = getExportScopeState({
    loading: isLoading,
    failed: Boolean(reportsError),
    matchingCount: reportsData?.pagination.total ?? 0,
    selectedCount: selectedReports.length,
    maxReports: config.max_reports,
  });
  const includedEvidenceLabels = packageContentOptions.filter((option) => Boolean(config[option.key])).map((option) => option.label);
  const packageScopeControls: PackageScopeControl[] = [
    {
      key: 'analyst_dispositions',
      label: 'Analyst disposition',
      options: analystDispositionOptions,
      value: handoffValueForDispositions(config.analyst_dispositions),
      onChange: (value) => handleConfigChange('analyst_dispositions', dispositionsForHandoff(value)),
    },
    {
      key: 'review_statuses',
      label: 'Lifecycle scope',
      options: handoffStateOptions,
      value: handoffValueForReviewStatuses(config.review_statuses),
      onChange: (value) => handleConfigChange('review_statuses', reviewStatusesForHandoff(value)),
    },
    {
      key: 'date_range_days',
      label: 'Review window',
      options: dateRangeFilterOptions,
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
      label: 'Minimum content quality',
      options: qualityFilterOptions,
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
      value: exportScope.packageScope,
      description: config.max_reports ? `Capped at ${config.max_reports} records before packaging.` : 'No record cap applied before packaging.',
    },
  ];
  const packageReadinessRows: PackageReadinessRow[] = [
    {
      label: 'File package',
      status: exportScope.readinessStatus === 'Ready' ? selectedFormat?.label ?? config.format.toUpperCase() : exportScope.readinessStatus,
      description: exportScope.readinessStatus === 'Ready' ? `${getFormatPreview()} ${exportScope.readinessDescription.toLowerCase()}` : exportScope.readinessDescription,
    },
    {
      label: 'Evidence queue',
      status: exportScope.queueStatus,
      description: exportScope.queueDescription,
    },
    {
      label: 'Scope constraints',
      status: config.max_reports ? `${config.max_reports} record cap` : 'No record cap',
      description: 'Disposition, lifecycle, review window, threat family, and content-quality constraints apply before packaging.',
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
                  Constrain the package by analyst judgment, lifecycle truth, evidence window, threat family, and content-quality floor.
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
                      Visible reports matching the handoff scope, with analyst disposition, readiness, content quality, and threat markers.
                    </p>
                  </div>
                  <button type="button" onClick={handleSelectAll} disabled={isLoading || Boolean(reportsError) || !reportsData?.reports.length} className="inline-flex h-9 shrink-0 items-center justify-center rounded-lg border border-zinc-300 bg-white px-3 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 disabled:pointer-events-none disabled:opacity-50">
                    {selectedReports.length > 0 && selectedReports.length === reportsData?.reports.length ? 'Clear selection' : 'Select visible'}
                  </button>
                </div>
                <div className="mt-4">
                  {isLoading ? (
                    <div className="space-y-3">
                      {[...Array(5)].map((_, i) => (
                        <div key={i} className="h-16 animate-pulse rounded-lg bg-zinc-100" />
                      ))}
                    </div>
                  ) : reportsError ? (
                    <div className="rounded-lg border border-red-200 bg-red-50 px-5 py-8 text-center" role="alert">
                      <p className="text-sm font-medium text-red-900">The handoff scope could not be loaded</p>
                      <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-red-700">
                        No package will be prepared until the matching records are available again.
                      </p>
                    </div>
                  ) : reportsData?.reports.length ? (
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
                  ) : (
                    <div className="rounded-lg border border-dashed border-zinc-300 px-5 py-8 text-center">
                      <p className="text-sm font-medium text-zinc-950">No accepted reports match this handoff</p>
                      <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-zinc-500">
                        Record an analyst disposition on a report, or broaden the disposition constraint for a non-handoff review package.
                      </p>
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
                disabled={exportMutation.isPending || !exportScope.canPrepare}
                className="flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-base font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
              >
                <ArrowDownTrayIcon className="h-5 w-5" aria-hidden="true" />
                {exportMutation.isPending ? 'Preparing package…' : exportScope.actionLabel}
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
          <span className="shrink-0 rounded-md bg-blue-50 px-2 py-0.5 text-sm font-medium text-blue-700">{record.quality}</span>
        </span>
        <span className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-sm text-zinc-500">{record.date}</span>
          <span className={`rounded-md px-2 py-0.5 text-sm font-medium ${getReviewStatusClasses(record.reviewStatus)}`}>
            {getReviewStatusLabel(record.reviewStatus)}
          </span>
          <span className={`rounded-md px-2 py-0.5 text-sm font-medium ${getAnalystDispositionClasses(record.analystDisposition)}`}>
            {getAnalystDispositionLabel(record.analystDisposition)}
          </span>
          {record.threatType ? (
            <span className="rounded-md bg-zinc-100 px-2 py-0.5 text-sm text-zinc-700">{record.threatType}</span>
          ) : null}
        </span>
      </span>
    </label>
  );
}
