'use client';

import React from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarIcon,
  DocumentTextIcon,
  PlusIcon,
  MagnifyingGlassIcon,
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
      title: 'Saved intelligence',
      value: analytics?.summary.total_reports ?? 0,
      icon: DocumentTextIcon,
      color: 'text-slate-700',
      bgColor: 'bg-slate-100',
    },
    {
      title: 'Briefed this week',
      value: analytics?.summary.reports_this_week ?? 0,
      icon: ChartBarIcon,
      color: 'text-emerald-700',
      bgColor: 'bg-emerald-50',
    },
    {
      title: 'Average confidence',
      value: analytics?.summary.avg_quality_score?.toFixed(1) ?? '0.0',
      icon: MagnifyingGlassIcon,
      color: 'text-indigo-700',
      bgColor: 'bg-indigo-50',
    },
  ];

  return (
    <AuthGuard>
      <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mb-8 max-w-3xl">
            <Badge variant="info" size="sm" className="mb-3 rounded-md">
              Intelligence briefing
            </Badge>
            <h1 className="text-2xl font-semibold leading-tight text-slate-950 sm:text-4xl">
              Review the current threat-intelligence workspace
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              Track generated reports, quality signals, and recent activity before opening the next investigation.
            </p>
          </div>

          <div className="mb-8">
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
              <Link href="/generate">
                <Button size="lg" className="min-h-11 w-full gap-2 sm:w-auto">
                  <PlusIcon className="h-5 w-5" />
                  <span>Generate intelligence</span>
                </Button>
              </Link>
              <Link href="/search">
                <Button variant="outline" size="lg" className="min-h-11 w-full gap-2 sm:w-auto">
                  <MagnifyingGlassIcon className="h-5 w-5" />
                  <span>Search intelligence</span>
                </Button>
              </Link>
              <Link href="/reports">
                <Button variant="outline" size="lg" className="min-h-11 w-full gap-2 sm:w-auto">
                  <DocumentTextIcon className="h-5 w-5" />
                  <span>Review saved reports</span>
                </Button>
              </Link>
            </div>
          </div>

          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
            {quickStats.map((stat) => {
              const Icon = stat.icon;
              return (
                <Card key={stat.title} className="border-slate-200 shadow-sm">
                  <CardContent className="flex items-center p-5">
                    <div className={`rounded-md p-3 ${stat.bgColor}`}>
                      <Icon className={`h-6 w-6 ${stat.color}`} />
                    </div>
                    <div className="ml-4">
                      <p className="text-sm font-medium text-slate-500">{stat.title}</p>
                      <p className="text-2xl font-semibold text-slate-950">{stat.value}</p>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
            <Card className="border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>Recent intelligence</CardTitle>
              </CardHeader>
              <CardContent>
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
                  <div className="space-y-4">
                    {recentReports.reports.map((report) => {
                      const qualityScore = formatQualityScore(report.quality_score);
                      return (
                        <div key={report.id} className="flex items-center justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <Link
                              href={`/reports/${report.id}`}
                              className="block truncate text-sm font-medium text-slate-950 hover:text-blue-600"
                            >
                              {report.tool_name}
                            </Link>
                            <p className="text-xs text-slate-500">
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
                    <div className="border-t border-slate-100 pt-4">
                      <Link href="/reports">
                        <Button variant="ghost" size="sm" className="w-full">
                          Review saved reports
                        </Button>
                      </Link>
                    </div>
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-slate-400" />
                    <p className="mb-4 text-slate-500">No saved intelligence yet</p>
                    <Link href="/generate">
                      <Button size="sm">Generate intelligence</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>Threat mix</CardTitle>
              </CardHeader>
              <CardContent>
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
                        <div key={threatType} className="flex items-center justify-between">
                          <span className="text-sm capitalize text-slate-600">
                            {threatType.replace(/_/g, ' ')}
                          </span>
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-16 rounded-full bg-slate-200">
                              <div
                                className="h-2 rounded-full bg-slate-700"
                                style={{
                                  width: `${Math.min(100, (count / Math.max(...Object.values(analytics.threat_distribution))) * 100)}%`
                                }}
                              ></div>
                            </div>
                            <span className="w-8 text-right text-sm font-medium text-slate-950">
                              {count}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <ChartBarIcon className="mx-auto mb-4 h-12 w-12 text-slate-400" />
                    <p className="text-slate-500">No threat mix available yet</p>
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
