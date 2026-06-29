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
import { formatRelativeTime, formatQualityScore } from '@/lib/utils';
import { ActivityFeed } from '@/components/ActivityFeed';
import { AuthGuard } from '@/components/AuthGuard';

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

  const { data: recentReports, isLoading: reportsLoading } = useQuery({
    queryKey: ['reports', 'recent'],
    queryFn: () => api.listReports(1, 5),
  });

  const threatCoverageRows = buildThreatCoverageRows(analytics?.threat_distribution);

  const briefingSignals = [
    {
      label: 'Intelligence library',
      value: analytics?.summary.total_reports ?? 0,
      detail: 'Saved reports ready for review',
    },
    {
      label: 'Briefed this week',
      value: analytics?.summary.reports_this_week ?? 0,
      detail: 'New intelligence generated',
    },
    {
      label: 'Analyst confidence',
      value: analytics?.summary.avg_quality_score?.toFixed(1) ?? '0.0',
      detail: 'Average report quality score',
    },
  ];

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
              Track generated reports, source coverage, and confidence before opening
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
              href="/search"
              className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-5 text-base font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
            >
              <MagnifyingGlassIcon className="h-5 w-5" aria-hidden="true" />
              Search intelligence
            </Link>
            <Link
              href="/reports"
              className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-5 text-base font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
            >
              <DocumentTextIcon className="h-5 w-5" aria-hidden="true" />
              Review saved reports
            </Link>
          </section>

          <dl
            data-contract="Dashboard.BriefingSignalStrip.v1"
            className="mt-8 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-3"
          >
            {briefingSignals.map((signal) => (
              <div key={signal.label} className="bg-white px-5 py-5">
                <dt className="text-sm text-zinc-500">{signal.label}</dt>
                <dd className="mt-1 text-2xl font-semibold text-zinc-950">{signal.value}</dd>
                <dd className="mt-0.5 text-sm text-zinc-500">{signal.detail}</dd>
              </div>
            ))}
          </dl>

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.85fr)_minmax(0,0.85fr)]">
            <section className="rounded-xl border border-zinc-200 bg-white p-5">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-base font-semibold text-zinc-950">Review queue</h2>
                <Link href="/reports" className="text-sm font-medium text-blue-700 hover:underline">
                  All reports
                </Link>
              </div>
              <p className="mt-1 text-sm text-zinc-500">Reopen reports for source context and confidence review.</p>
              <div className="mt-4">
                {reportsLoading ? (
                  <div className="space-y-3" role="status" aria-label="Loading recent reports">
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="h-10 animate-pulse rounded-lg bg-zinc-100" />
                    ))}
                  </div>
                ) : recentReports?.reports.length ? (
                  <ul className="divide-y divide-zinc-100">
                    {recentReports.reports.map((report) => {
                      const qualityScore = formatQualityScore(report.quality_score);
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
                          <span className="shrink-0 rounded-md bg-zinc-100 px-2 py-1 font-mono text-sm text-zinc-700">
                            {qualityScore.formatted}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
                    <p className="text-sm font-medium text-zinc-950">No reports yet</p>
                    <p className="mt-1 text-sm text-zinc-500">Generate your first report to start the review queue.</p>
                    <Link
                      href="/generate"
                      className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-blue-700 hover:underline"
                    >
                      Generate intelligence
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
