'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api, type GenerationErrorCode } from '@/lib/api';
import { formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';
import { getAnalystDispositionClasses, getAnalystDispositionLabel } from '@/lib/analyst-disposition';

const timeRangeOptions = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
];

const routeLabels = {
  primary: 'Requested synthesis route',
  fallback: 'Fallback synthesis route',
  legacy_aggregate: 'Legacy aggregate route',
  unrecorded: 'Legacy / unrecorded',
} as const;

const failureCauseLabels: Record<GenerationErrorCode, string> = {
  provider_rate_limited: 'Provider rate limited',
  provider_unavailable: 'Provider route unavailable',
  provider_timeout: 'Provider timed out',
  model_request_rejected: 'Model request rejected',
  model_output_invalid: 'Model output invalid',
  evidence_unavailable: 'Evidence unavailable',
  evidence_unattested: 'Evidence could not be attested',
  evidence_incomplete: 'Generated evidence coverage incomplete',
  evidence_inadmissible: 'Evidence unsafe for operational use',
  persistence_failed: 'Report could not be saved',
  unknown: 'Legacy / unrecorded cause',
};

function humanizeStage(value: string): string {
  const labels: Record<string, string> = {
    queued: 'Preparing research',
    researching: 'Researching sources',
    synthesizing: 'Authoring report',
    validating: 'Validating sections',
    finalizing: 'Saving record',
    unknown: 'Unrecorded stage',
  };
  return labels[value] ?? 'Unrecorded stage';
}

export default function AnalyticsPage() {
  const [timeRange, setTimeRange] = useState('30d');

  const { data: analytics, isLoading, error } = useQuery({
    queryKey: ['analytics', timeRange],
    queryFn: () => api.getAnalytics(timeRange),
  });

  if (isLoading) {
    return (
      <AuthGuard>
        <main
          className="min-h-[60vh] overflow-x-hidden bg-[var(--surface-0)] px-6 py-16 lg:px-8"
          role="status"
          aria-label="Preparing operations metrics"
        >
          <div className="mx-auto max-w-md rounded-xl border border-zinc-200 bg-white px-6 py-10 text-center">
            <div className="mx-auto mb-5 h-8 w-8 animate-spin rounded-full border-2 border-zinc-200 border-t-zinc-800" />
            <h1 className="text-xl font-semibold text-zinc-950">Preparing operations metrics</h1>
            <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-zinc-500">
              Loading report volume, quality signals, and threat distribution for this window.
            </p>
          </div>
        </main>
      </AuthGuard>
    );
  }

  if (error) {
    return (
      <AuthGuard>
        <main className="overflow-x-hidden bg-[var(--surface-0)] px-6 py-16 lg:px-8">
          <div className="mx-auto max-w-2xl">
            <h1 className="text-3xl font-semibold tracking-tight text-zinc-950">
              Intelligence operations review
            </h1>
            <div role="alert" className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm leading-6 text-red-700">
              Operations metrics are not available right now. Refresh the workspace or return once the backend is reachable.
            </div>
          </div>
        </main>
      </AuthGuard>
    );
  }

  const overview = analytics?.overview;
  const reportsPeriod = overview?.reports_in_period ?? 0;
  const recentActivity = analytics?.recent_activity ?? [];
  const threatEntries = analytics?.trends.threat_type_distribution.slice(0, 5) ?? [];
  const maxThreatCount = Math.max(1, ...threatEntries.map((entry) => entry.count));
  const shownRecentActivity = recentActivity.slice(0, 5);
  const routePerformance = analytics?.route_performance ?? [];
  const generationFailures = analytics?.generation_failure_breakdown ?? [];
  const metricSignals = [
    {
      label: 'Reports in window',
      value: reportsPeriod,
      detail: `${overview?.total_reports ?? 0} saved across the workspace`,
    },
    {
      label: 'Content quality',
      value: overview?.avg_quality_score == null ? '—' : overview.avg_quality_score.toFixed(2),
      detail: overview?.scored_reports
        ? `${overview.scored_reports} of ${reportsPeriod} reports scored`
        : 'No scored reports in this window',
    },
    {
      label: 'Unresolved work',
      value: overview?.unresolved_reports ?? 0,
      detail: `${overview?.accepted_reports ?? 0} accepted · ${overview?.generation_failed_reports ?? 0} generation failures`,
    },
    {
      label: 'Generation completion',
      value: overview?.generation_completion_rate == null
        ? '—'
        : `${Math.round(overview.generation_completion_rate * 100)}%`,
      detail: overview?.terminal_reports
        ? `${overview.terminal_reports} terminal generation records`
        : 'No terminal generation records',
    },
  ];

  return (
    <AuthGuard>
      <main data-surface="analytics-review" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-2xl">
              <p className="text-sm font-medium text-blue-700">Operations metrics</p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">
                Intelligence operations review
              </h1>
              <p className="mt-4 text-lg leading-8 text-zinc-600">
                Report volume, quality signals, and threat distribution for the
                selected window.
              </p>
            </div>
            <label className="block min-w-0 sm:w-56">
              <span className="block text-sm font-medium text-zinc-800">Review window</span>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="mt-2 block h-11 w-full rounded-lg border border-zinc-300 bg-white px-3 text-base text-zinc-950 outline-none transition-colors focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
              >
                {timeRangeOptions.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </label>
          </div>

          <dl
            data-contract="Analytics.MetricSignalStrip.v1"
            className="mt-10 grid gap-6 border-y border-zinc-200 py-6 sm:grid-cols-2 xl:grid-cols-4"
          >
            {metricSignals.map((metric) => (
              <div key={metric.label} className="min-w-0">
                <dt className="text-sm text-zinc-500">{metric.label}</dt>
                <dd className="mt-1 text-2xl font-semibold text-zinc-950">{metric.value}</dd>
                <dd className="mt-0.5 text-sm leading-6 text-zinc-500">{metric.detail}</dd>
              </div>
            ))}
          </dl>

          <section
            data-contract="Analytics.GenerationRouteComparison.v1"
            className="mt-10 min-w-0 border-t border-zinc-200 pt-6"
          >
            <h2 className="text-base font-semibold text-zinc-950">Generation route comparison</h2>
            <p className="mt-1 text-sm leading-6 text-zinc-500">
              Compare completed reports by the synthesis route that authored them. Older aggregate provenance stays separate rather than implying an unrecorded role.
            </p>
            <div className="mt-5 grid gap-x-8 gap-y-5 md:grid-cols-2 xl:grid-cols-4">
              {routePerformance.map((route) => (
                <dl key={route.route} className="min-w-0 border-t border-zinc-200 pt-4">
                  <dt className="text-sm font-medium text-zinc-700">{routeLabels[route.route]}</dt>
                  <dd className="mt-1 text-2xl font-semibold text-zinc-950">{route.report_count}</dd>
                  <dd className="mt-2 text-sm leading-6 text-zinc-500">
                    {route.avg_quality_score == null
                      ? 'Content quality not scored'
                      : `${route.avg_quality_score.toFixed(2)} average content quality`}
                    {` · ${route.scored_report_count}/${route.report_count} scored`}
                    <br />
                    {route.avg_processing_time_ms == null
                      ? 'Runtime not recorded'
                      : `${formatProcessingTime(route.avg_processing_time_ms)} average runtime`}
                    {` · ${route.runtime_recorded_count}/${route.report_count} recorded`}
                  </dd>
                </dl>
              ))}
            </div>
          </section>

          <section
            data-contract="Analytics.GenerationFailureEvidence.v1"
            className="mt-10 min-w-0 border-t border-zinc-200 pt-6"
          >
            <h2 className="text-base font-semibold text-zinc-950">Generation failure evidence</h2>
            <p className="mt-1 text-sm leading-6 text-zinc-500">
              Typed failures grouped by cause, last pipeline stage, route, and UTC hour. Unknown history stays unrecorded.
            </p>
            {generationFailures.length > 0 ? (
              <div className="mt-4 overflow-x-auto rounded-lg border border-zinc-200">
                <table className="w-full min-w-[44rem] border-collapse text-left text-sm">
                  <thead className="bg-zinc-100 text-zinc-950">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Cause</th>
                      <th className="px-3 py-2 font-semibold">Count</th>
                      <th className="px-3 py-2 font-semibold">Last stages</th>
                      <th className="px-3 py-2 font-semibold">Routes</th>
                      <th className="px-3 py-2 font-semibold">UTC hours</th>
                    </tr>
                  </thead>
                  <tbody>
                    {generationFailures.map((failure) => (
                      <tr key={failure.error_code} className="border-t border-zinc-200 align-top">
                        <td className="px-3 py-3 font-medium text-zinc-950">{failureCauseLabels[failure.error_code]}</td>
                        <td className="px-3 py-3 text-zinc-700">{failure.report_count}</td>
                        <td className="px-3 py-3 text-zinc-600">{Object.entries(failure.stages).map(([key, value]) => `${humanizeStage(key)}: ${value}`).join(' · ')}</td>
                        <td className="px-3 py-3 text-zinc-600">{Object.entries(failure.routes).filter(([, value]) => value > 0).map(([key, value]) => `${key}: ${value}`).join(' · ')}</td>
                        <td className="px-3 py-3 text-zinc-600">{Object.entries(failure.utc_hours).map(([key, value]) => `${key}: ${value}`).join(' · ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="mt-4 rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-sm text-zinc-500">
                No typed generation failures were recorded in this window.
              </p>
            )}
          </section>

          <div className="mt-10 grid grid-cols-1 gap-x-10 gap-y-10 lg:grid-cols-2">
            <section className="min-w-0 border-t border-zinc-200 pt-6">
              <h2 className="text-base font-semibold text-zinc-950">Review timeline</h2>
              <p className="mt-1 text-sm text-zinc-500">Recent report activity in this window.</p>
              <div className="mt-4">
                {shownRecentActivity.length > 0 ? (
                  <ul className="divide-y divide-zinc-100">
                    {shownRecentActivity.map((activity, index) => (
                      <li key={activity.id} className="flex min-w-0 items-center justify-between gap-3 py-3 first:pt-0">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-zinc-950">
                            {activity.tool_name || `Report ${index + 1}`}
                          </p>
                          <p className="text-sm text-zinc-500">
                            {activity.created_at ? formatRelativeTime(activity.created_at) : 'Recently'}
                            {activity.generation_route_scope === 'legacy_aggregate' ? (
                              <span className="ml-2 rounded-md bg-zinc-100 px-2 py-0.5 font-medium text-zinc-700">
                                Legacy aggregate route
                              </span>
                            ) : activity.generation_route_scope === 'synthesis' && activity.generation_used_fallback === true ? (
                              <span className="ml-2 rounded-md bg-amber-50 px-2 py-0.5 font-medium text-amber-700">
                                Fallback synthesis route
                              </span>
                            ) : null}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-col items-end gap-1 text-sm">
                          <span className="text-zinc-700">
                            {activity.quality_score != null
                              ? `Content quality: ${activity.quality_score.toFixed(2)}`
                              : 'Content quality: Not scored'}
                          </span>
                          <span className="capitalize text-zinc-500">
                            {activity.review_status.replace(/_/g, ' ')}
                          </span>
                          {activity.eligible_for_judgment ? (
                            <span className={`rounded-md px-2 py-0.5 font-medium ${getAnalystDispositionClasses(activity.analyst_disposition)}`}>
                              {getAnalystDispositionLabel(activity.analyst_disposition)}
                            </span>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
                    <p className="text-sm text-zinc-500">No recent report activity in this window.</p>
                  </div>
                )}
              </div>
            </section>

            <section className="min-w-0 border-t border-zinc-200 pt-6">
              <h2 className="text-base font-semibold text-zinc-950">Threat coverage map</h2>
              <p className="mt-1 text-sm text-zinc-500">Threat distribution across saved reports.</p>
              <div className="mt-4">
                {threatEntries.length > 0 ? (
                  <div className="space-y-3">
                    {threatEntries.map(({ threat_type: type, count }) => {
                      const percentage = Math.min((count / maxThreatCount) * 100, 100);
                      return (
                        <div key={type} className="flex min-w-0 items-center justify-between gap-3">
                          <span className="min-w-0 flex-1 truncate text-sm capitalize text-zinc-700">
                            {type.replace(/_/g, ' ')}
                          </span>
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-24 rounded-full bg-zinc-200">
                              <div className="h-2 rounded-full bg-blue-600" style={{ width: `${percentage}%` }} />
                            </div>
                            <span className="w-8 text-right text-sm font-medium tabular-nums text-zinc-950">{count}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
                    <p className="text-sm text-zinc-500">Coverage appears after reports classify threat patterns.</p>
                  </div>
                )}
              </div>
            </section>
          </div>
        </div>
      </main>
    </AuthGuard>
  );
}
