'use client';

import React from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import { ActivityFeed } from '@/components/ActivityFeed';
import { AuthGuard } from '@/components/AuthGuard';
import { DashboardBriefingSignals } from '@/components/DashboardBriefingSignals';
import { getQualityLabel } from '@/lib/report-query';
import { getReviewStatusClasses, getReviewStatusLabel } from '@/lib/report-status';
import { getAnalystDispositionClasses, getAnalystDispositionLabel } from '@/lib/analyst-disposition';

const THREAT_COVERAGE_ROW_LIMIT = 5;

type ThreatCoverageRow = {
  threatType: string;
  label: string;
  count: number;
  coveragePercent: number;
};

function formatThreatCoverageLabel(threatType: string) {
  return threatType.replace(/_/g, ' ');
}

function buildThreatCoverageRows(distribution?: Record<string, number>): ThreatCoverageRow[] {
  if (!distribution) {
    return [];
  }

  const entries = Object.entries(distribution)
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort(([, a], [, b]) => b - a)
    .slice(0, THREAT_COVERAGE_ROW_LIMIT);

  const maxCount = Math.max(...entries.map(([, count]) => count), 0);

  return entries.map(([threatType, count]) => ({
    threatType,
    label: formatThreatCoverageLabel(threatType),
    count,
    coveragePercent: maxCount > 0 ? Math.max(8, Math.round((count / maxCount) * 100)) : 0,
  }));
}

export default function Dashboard() {
  const { data: analytics, isLoading: analyticsLoading, error: analyticsError } = useQuery({
    queryKey: ['analytics', 'dashboard'],
    queryFn: () => api.getDashboardAnalytics(),
  });

  const {
    data: recentReports,
    isLoading: reportsLoading,
    error: reportsError,
    refetch: refetchReports,
  } = useQuery({
    queryKey: ['reports', 'recent'],
    queryFn: () => api.listReports(1, 5, {
      requires_action: true,
    }),
  });

  const threatCoverageRows = buildThreatCoverageRows(analytics?.threat_distribution);

  return (
    <AuthGuard>
      <main data-surface="dashboard-workspace" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <header className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">Briefing</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">
              Your intelligence workspace
            </h1>
            <p className="mt-4 text-lg leading-8 text-zinc-600">
              Track generated reports, source coverage, and review readiness before opening
              the next investigation.
            </p>
          </header>

          <section
            data-contract="Action.PrimaryInvestigation.v1"
            className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap"
          >
            <Link
              href="/generate"
              className="group inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-base font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2"
            >
              <PlusIcon className="h-5 w-5" aria-hidden="true" />
              Generate intelligence
            </Link>
            <Link
              href="/reports"
              className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-5 text-base font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
            >
              <MagnifyingGlassIcon className="h-5 w-5" aria-hidden="true" />
              Search and filter reports
            </Link>
            <Link
              href="/reports"
              className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-5 text-base font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
            >
              <DocumentTextIcon className="h-5 w-5" aria-hidden="true" />
              Review saved reports
            </Link>
          </section>

          <DashboardBriefingSignals analytics={analytics} isLoading={analyticsLoading} />

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.85fr)_minmax(0,0.85fr)]">
            <section className="rounded-xl border border-zinc-200 bg-white p-5">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-base font-semibold text-zinc-950">Review queue</h2>
                <Link href="/reports?review_state=all" className="text-sm font-medium text-blue-700 hover:underline">
                  All reports
                </Link>
              </div>
              <p className="mt-1 text-sm text-zinc-500">Continue failed runs, evaluation recovery, and unresolved analyst judgments.</p>
              <div className="mt-4">
                {reportsLoading ? (
                  <div className="space-y-3" role="status" aria-label="Loading recent reports">
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="h-10 animate-pulse rounded-lg bg-zinc-100" />
                    ))}
                  </div>
                ) : reportsError ? (
                  <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-5" role="alert">
                    <p className="text-sm font-medium text-red-900">Couldn&apos;t load your reports</p>
                    <p className="mt-1 text-sm leading-6 text-red-700">
                      The review queue is unavailable right now. Your saved records have not been removed.
                    </p>
                    <button
                      type="button"
                      onClick={() => refetchReports()}
                      className="mt-3 text-sm font-medium text-red-800 underline underline-offset-4 hover:text-red-900"
                    >
                      Retry loading reports
                    </button>
                  </div>
                ) : recentReports?.reports.length ? (
                  <ul className="divide-y divide-zinc-100">
                    {recentReports.reports.map((report) => {
                      const qualityLabel = getQualityLabel(report.quality_score);
                      return (
                        <li key={report.id} className="flex items-center justify-between gap-3 py-3 first:pt-0">
                          <div className="min-w-0">
                            <Link
                              href={`/reports/${report.id}`}
                              className="block truncate text-sm font-medium text-zinc-950 hover:text-blue-700"
                            >
                              {report.tool_name}
                            </Link>
                            <p className="text-sm text-zinc-500">{formatRelativeTime(report.created_at)}</p>
                          </div>
                          <div className="flex shrink-0 flex-col items-end gap-1">
                            <span className="rounded-md bg-zinc-100 px-2 py-1 text-sm text-zinc-700">
                              {qualityLabel}{report.quality_score == null ? '' : ` · ${Number(report.quality_score).toFixed(2)}`}
                            </span>
                            <span className={`rounded-md px-2 py-1 text-sm font-medium ${getReviewStatusClasses(report.review_status)}`}>
                              {getReviewStatusLabel(report.review_status)}
                            </span>
                            <span className={`rounded-md px-2 py-1 text-sm font-medium ${getAnalystDispositionClasses(report.analyst_disposition)}`}>
                              {getAnalystDispositionLabel(report.analyst_disposition)}
                            </span>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
                    <p className="text-sm font-medium text-zinc-950">
                      {(analytics?.summary.total_reports ?? 0) > 0 ? 'No reports need action' : 'No reports yet'}
                    </p>
                    <p className="mt-1 text-sm text-zinc-500">
                      {(analytics?.summary.total_reports ?? 0) > 0
                        ? 'Your saved archive remains available; no runs currently need retry, evaluation, revision, or analyst judgment.'
                        : 'Generate your first report to start the review queue.'}
                    </p>
                    <Link
                      href={(analytics?.summary.total_reports ?? 0) > 0 ? '/reports?review_state=all' : '/generate'}
                      className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-blue-700 hover:underline"
                    >
                      {(analytics?.summary.total_reports ?? 0) > 0 ? 'Open all reports' : 'Generate intelligence'}
                      <ArrowRightIcon className="h-4 w-4" aria-hidden="true" />
                    </Link>
                  </div>
                )}
              </div>
            </section>

            <section data-contract="Dashboard.ThreatCoverageMap.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
              <h2 className="text-base font-semibold text-zinc-950">Coverage map</h2>
              <p className="mt-1 text-sm text-zinc-500">Threat patterns represented in saved reports.</p>
              <div className="mt-4">
                {analyticsLoading ? (
                  <div className="space-y-3" role="status" aria-label="Loading coverage map">
                    {[...Array(4)].map((_, i) => (
                      <div key={i} className="h-4 animate-pulse rounded bg-zinc-100" />
                    ))}
                  </div>
                ) : threatCoverageRows.length > 0 ? (
                  <div className="space-y-3">
                    {threatCoverageRows.map((row) => (
                      <div key={row.threatType} className="flex items-center justify-between gap-3">
                        <span className="min-w-0 flex-1 truncate text-sm capitalize text-zinc-700">{row.label}</span>
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-16 rounded-full bg-zinc-200">
                            <div className="h-2 rounded-full bg-blue-600" style={{ width: `${row.coveragePercent}%` }} />
                          </div>
                          <span className="w-8 text-right font-mono text-sm text-zinc-950">{row.count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
                    <p className="text-sm text-zinc-500">Coverage appears once reports classify threat patterns.</p>
                  </div>
                )}
              </div>
            </section>

            <ActivityFeed limit={6} compact={true} />
          </div>

          {analyticsError && (
            <div role="alert" className="mt-8 rounded-xl border border-red-200 bg-red-50 p-4">
              <p className="text-sm font-medium text-red-900">The briefing could not refresh</p>
              <p className="mt-1 text-sm leading-6 text-red-700">
                Try again shortly, or continue with saved reports while the data source reconnects.
              </p>
            </div>
          )}
        </div>
      </main>
    </AuthGuard>
  );
}
