'use client';

import React from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarIcon,
  DocumentTextIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  ShieldCheckIcon,
  ArrowTrendingUpIcon,
  ClipboardDocumentCheckIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatRelativeTime, formatQualityScore } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ActivityFeed } from '@/components/ActivityFeed';
import { AuthGuard } from '@/components/AuthGuard';

export default function Dashboard() {
  const { data: analytics, isLoading: analyticsLoading, error: analyticsError } = useQuery({
    queryKey: ['analytics', 'dashboard'],
    queryFn: () => api.getDashboardAnalytics(),
  });

  const { data: recentReports, isLoading: reportsLoading } = useQuery({
    queryKey: ['reports', 'recent'],
    queryFn: () => api.listReports(1, 5),
  });

  const quickStats = [
    {
      title: 'Intelligence library',
      value: analytics?.summary.total_reports ?? 0,
      detail: 'Saved reports ready for review',
      icon: DocumentTextIcon,
      accent: 'border-l-cyan-500',
      iconTone: 'bg-cyan-50 text-cyan-700',
    },
    {
      title: 'Briefed this week',
      value: analytics?.summary.reports_this_week ?? 0,
      detail: 'New intelligence generated',
      icon: ChartBarIcon,
      accent: 'border-l-emerald-500',
      iconTone: 'bg-emerald-50 text-emerald-700',
    },
    {
      title: 'Analyst confidence',
      value: analytics?.summary.avg_quality_score?.toFixed(1) ?? '0.0',
      detail: 'Average report quality score',
      icon: MagnifyingGlassIcon,
      accent: 'border-l-amber-500',
      iconTone: 'bg-amber-50 text-amber-700',
    },
  ];

  return (
    <AuthGuard>
      <div data-surface="dashboard-workspace" className="min-h-screen overflow-x-hidden bg-zinc-50 py-6 sm:py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <section className="mb-8 border-y border-zinc-200 bg-white px-4 py-6 shadow-sm sm:px-6 lg:px-8">
            <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_21rem] lg:items-end">
              <div className="max-w-3xl">
                <Badge variant="info" size="sm" className="mb-3 rounded-md bg-cyan-50 text-cyan-800">
                  Intelligence briefing
                </Badge>
                <h1 className="text-2xl font-semibold leading-tight text-zinc-950 sm:text-4xl">
                  Review the current threat-intelligence workspace
                </h1>
                <p className="mt-3 max-w-2xl text-base leading-7 text-zinc-600 sm:text-lg">
                  Track generated reports, source coverage, and confidence signals before opening the next investigation.
                </p>
              </div>

              <div className="rounded-md border border-zinc-200 bg-zinc-50 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Source posture</p>
                    <p className="mt-1 text-sm text-zinc-700">Local briefing state, saved reports, and activity signals.</p>
                  </div>
                  <div className="rounded-md bg-white p-2 text-emerald-700 shadow-sm">
                    <ShieldCheckIcon className="h-5 w-5" />
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-8 grid gap-4 lg:grid-cols-[minmax(0,1fr)_21rem]">
            <div data-contract="Action.PrimaryInvestigation.v1" className="rounded-md border border-zinc-200 bg-white p-4 shadow-sm">
              <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-zinc-950">Next investigation</p>
                  <p className="text-sm text-zinc-500">Start from generation, search, or the report library.</p>
                </div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                <Link href="/generate">
                  <Button size="lg" className="min-h-11 w-full gap-2 rounded-md bg-zinc-950 hover:bg-zinc-800 sm:w-auto">
                    <PlusIcon className="h-5 w-5" />
                    <span>Generate intelligence</span>
                  </Button>
                </Link>
                <Link href="/search">
                  <Button variant="outline" size="lg" className="min-h-11 w-full gap-2 rounded-md border-zinc-300 text-zinc-800 sm:w-auto">
                    <MagnifyingGlassIcon className="h-5 w-5" />
                    <span>Search intelligence</span>
                  </Button>
                </Link>
                <Link href="/reports">
                  <Button variant="outline" size="lg" className="min-h-11 w-full gap-2 rounded-md border-zinc-300 text-zinc-800 sm:w-auto">
                    <DocumentTextIcon className="h-5 w-5" />
                    <span>Review saved reports</span>
                  </Button>
                </Link>
              </div>
            </div>

            <aside className="rounded-md border border-zinc-200 bg-zinc-950 p-4 text-white shadow-sm">
              <p className="text-xs font-semibold uppercase tracking-wide text-cyan-200">Operations rail</p>
              <p className="mt-2 text-sm leading-6 text-zinc-200">
                Use this workspace to reconcile source gaps, stale briefings, and confidence changes before escalation.
              </p>
            </aside>
          </section>

          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            {quickStats.map((stat) => {
              const Icon = stat.icon;
              return (
                <Card key={stat.title} className={`border-l-4 border-zinc-200 shadow-sm ${stat.accent}`}>
                  <CardContent className="flex items-start gap-4 p-5">
                    <div className={`rounded-md p-3 ${stat.iconTone}`}>
                      <Icon className="h-6 w-6" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-zinc-500">{stat.title}</p>
                      <p className="text-2xl font-semibold text-zinc-950">{stat.value}</p>
                      <p className="mt-1 text-xs leading-5 text-zinc-500">{stat.detail}</p>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(17rem,0.85fr)_minmax(17rem,0.85fr)]">
            <Card className="border-zinc-200 shadow-sm">
              <CardHeader className="border-b border-zinc-100 pb-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Review queue</p>
                    <CardTitle className="mt-1 text-base text-zinc-950">Recent intelligence</CardTitle>
                  </div>
                  <ClipboardDocumentCheckIcon className="h-5 w-5 text-zinc-500" />
                </div>
                <p className="mt-2 text-xs leading-5 text-zinc-500">Reopen reports for source context and confidence review.</p>
              </CardHeader>
              <CardContent className="pt-1">
                {reportsLoading ? (
                  <div className="space-y-4">
                    {[...Array(3)].map((_, i) => (
                      <div key={i} className="animate-pulse">
                        <div className="mb-2 h-4 w-3/4 rounded bg-slate-200"></div>
                        <div className="h-3 w-1/2 rounded bg-slate-200"></div>
                      </div>
                    ))}
                  </div>
                ) : recentReports?.reports.length ? (
                  <div className="divide-y divide-zinc-100">
                    {recentReports.reports.map((report) => {
                      const qualityScore = formatQualityScore(report.quality_score);
                      return (
                        <div key={report.id} className="flex items-center justify-between gap-3 py-3 first:pt-0">
                          <div className="min-w-0 flex-1">
                            <Link
                              href={`/reports/${report.id}`}
                              className="block truncate text-sm font-semibold text-zinc-950 hover:text-cyan-700"
                            >
                              {report.tool_name}
                            </Link>
                            <p className="text-xs text-zinc-500">
                              {formatRelativeTime(report.created_at)}
                            </p>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Badge
                              variant={
                                report.quality_score >= 4.0 ? 'success' :
                                report.quality_score >= 3.0 ? 'info' :
                                report.quality_score >= 2.0 ? 'warning' : 'error'
                              }
                              size="sm"
                            >
                              {qualityScore.formatted}
                            </Badge>
                          </div>
                        </div>
                      );
                    })}
                    <div className="pt-4">
                      <Link href="/reports">
                        <Button variant="ghost" size="sm" className="w-full rounded-md text-zinc-800 hover:bg-zinc-100">
                          Review saved reports
                        </Button>
                      </Link>
                    </div>
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-zinc-400" />
                    <p className="mb-4 text-zinc-500">No saved intelligence is queued for review yet</p>
                    <Link href="/generate">
                      <Button size="sm" className="rounded-md">Generate intelligence</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-zinc-200 shadow-sm">
              <CardHeader className="border-b border-zinc-100 pb-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Coverage map</p>
                    <CardTitle className="mt-1 text-base text-zinc-950">Threat patterns</CardTitle>
                  </div>
                  <ArrowTrendingUpIcon className="h-5 w-5 text-zinc-500" />
                </div>
                <p className="mt-2 text-xs leading-5 text-zinc-500">Analyst triage view of the patterns represented in saved reports.</p>
              </CardHeader>
              <CardContent className="pt-1">
                {analyticsLoading ? (
                  <div className="space-y-3">
                    {[...Array(4)].map((_, i) => (
                      <div key={i} className="animate-pulse">
                        <div className="h-3 w-full rounded bg-slate-200"></div>
                      </div>
                    ))}
                  </div>
                ) : analytics?.threat_distribution && Object.keys(analytics.threat_distribution).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(analytics.threat_distribution)
                      .sort(([,a], [,b]) => b - a)
                      .slice(0, 5)
                      .map(([threatType, count]) => (
                        <div key={threatType} className="flex items-center justify-between gap-3">
                          <span className="min-w-0 flex-1 truncate text-sm capitalize text-zinc-700">
                            {threatType.replace(/_/g, ' ')}
                          </span>
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-16 rounded-full bg-zinc-200">
                              <div
                                className="h-2 rounded-full bg-emerald-700"
                                style={{
                                  width: `${Math.min(100, (count / Math.max(...Object.values(analytics.threat_distribution))) * 100)}%`
                                }}
                              ></div>
                            </div>
                            <span className="w-8 text-right text-sm font-semibold text-zinc-950">
                              {count}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <ChartBarIcon className="mx-auto mb-4 h-12 w-12 text-zinc-400" />
                    <p className="text-zinc-500">Coverage appears after reports classify threat patterns</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <ActivityFeed limit={6} compact={true} />
          </div>

          {analyticsError && (
            <Card variant="outlined" className="mt-8 border-red-200 bg-red-50">
              <CardContent>
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="h-5 w-5 text-red-400">!</div>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">
                      The briefing could not refresh
                    </h3>
                    <p className="mt-1 text-sm text-red-600">
                      Try again shortly or continue with saved reports while the data source reconnects.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </AuthGuard>
  );
}
