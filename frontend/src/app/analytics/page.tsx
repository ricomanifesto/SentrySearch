'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api } from '@/lib/api';
import { formatProcessingTime, formatRelativeTime } from '@/lib/utils';
import { AuthGuard } from '@/components/AuthGuard';

const timeRangeOptions = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
];

const routeLabels = {
  primary: 'Requested route',
  fallback: 'Fallback route',
  unrecorded: 'Legacy / unrecorded',
} as const;

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
  const metricSignals = [
    {
      label: 'Reports in window',
      value: reportsPeriod,
      detail: `${overview?.total_reports ?? 0} saved across the workspace`,
    },
    {
      label: 'Report quality',
      value: overview?.avg_quality_score == null ? '—' : overview.avg_quality_score.toFixed(2),
      detail: overview?.scored_reports
        ? `${overview.scored_reports} of ${reportsPeriod} reports scored`
        : 'No scored reports in this window',
    },
    {
      label: 'Needs attention',
      value: overview?.needs_attention_reports ?? 0,
      detail: `${overview?.evaluation_failed_reports ?? 0} evaluator failures`,
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
            className="mt-8 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-2 xl:grid-cols-4"
          >
            {metricSignals.map((metric) => (
              <div key={metric.label} className="min-w-0 bg-white px-5 py-5">
                <dt className="text-sm text-zinc-500">{metric.label}</dt>
                <dd className="mt-1 text-2xl font-semibold text-zinc-950">{metric.value}</dd>
                <dd className="mt-0.5 text-sm leading-6 text-zinc-500">{metric.detail}</dd>
              </div>
            ))}
          </dl>

          <section
            data-contract="Analytics.GenerationRouteComparison.v1"
            className="mt-8 min-w-0 rounded-xl border border-zinc-200 bg-white p-5"
          >
            <h2 className="text-base font-semibold text-zinc-950">Generation route comparison</h2>
            <p className="mt-1 text-sm leading-6 text-zinc-500">
              Compare completed reports by the route that actually produced them. Older records stay visibly unrecorded.
            </p>
            <div className="mt-4 grid gap-px overflow-hidden rounded-lg border border-zinc-200 bg-zinc-200 md:grid-cols-3">
              {routePerformance.map((route) => (
                <dl key={route.route} className="min-w-0 bg-white p-4">
                  <dt className="text-sm font-medium text-zinc-700">{routeLabels[route.route]}</dt>
                  <dd className="mt-1 text-2xl font-semibold text-zinc-950">{route.report_count}</dd>
                  <dd className="mt-2 text-sm leading-6 text-zinc-500">
                    {route.avg_quality_score == null
                      ? 'Quality not scored'
                      : `${route.avg_quality_score.toFixed(2)} average report quality`}
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

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <section className="min-w-0 rounded-xl border border-zinc-200 bg-white p-5">
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
                            {activity.generation_used_fallback === true ? (
                              <span className="ml-2 rounded-md bg-amber-50 px-2 py-0.5 font-medium text-amber-700">
                                Fallback route
                              </span>
                            ) : null}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-col items-end gap-1 text-sm">
                          <span className="text-zinc-700">
                            {activity.quality_score != null
                              ? `Quality: ${activity.quality_score.toFixed(2)}`
                              : 'Quality: Not scored'}
                          </span>
                          <span className="capitalize text-zinc-500">
                            {activity.review_status.replace(/_/g, ' ')}
                          </span>
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

            <section className="min-w-0 rounded-xl border border-zinc-200 bg-white p-5">
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
                            <span className="w-8 text-right font-mono text-sm text-zinc-950">{count}</span>
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
