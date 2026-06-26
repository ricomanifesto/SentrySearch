'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  ChartBarIcon,
  ClockIcon,
  ShieldCheckIcon,
  ArrowTrendingUpIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';
import { AuthGuard } from '@/components/AuthGuard';
import { SurfaceHeader } from '@/components/ui/SurfaceHeader';

const timeRangeOptions = [
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: '90d', label: 'Last 90 Days' },
];

export default function AnalyticsPage() {
  const [timeRange, setTimeRange] = useState('30d');

  const { data: analytics, isLoading, error } = useQuery({
    queryKey: ['analytics', timeRange],
    queryFn: () => api.getAnalytics(timeRange),
  });

  const { data: dashboard } = useQuery({
    queryKey: ['analytics', 'dashboard'],
    queryFn: () => api.getDashboardAnalytics(),
  });

  if (isLoading) {
    return (
      <AuthGuard>
        <div
          className="min-h-screen overflow-x-hidden bg-slate-50 px-4 py-12 text-slate-950 sm:px-6 lg:px-8"
          role="status"
          aria-label="Preparing operations metrics"
        >
          <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-3xl items-center justify-center">
            <div className="w-full border border-slate-200 bg-white px-6 py-8 text-center shadow-sm sm:px-10">
              <div className="mx-auto mb-5 h-10 w-10 animate-spin border-2 border-slate-200 border-t-slate-800" />
              <h1 className="text-2xl font-semibold text-slate-950">Preparing operations metrics</h1>
              <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-slate-600">
                Loading report volume, quality signals, and threat distribution for this review window.
              </p>
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  if (error) {
    return (
      <AuthGuard>
        <div className="min-h-screen overflow-x-hidden bg-slate-50 px-4 py-12 text-slate-950 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-3xl">
            <div className="mb-6">
              <Badge variant="error" size="sm">Metrics unavailable</Badge>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-slate-950">
                Intelligence operations review
              </h1>
            </div>
            <div role="alert" className="border border-red-200 bg-red-50 p-4 text-sm leading-6 text-red-700">
              Operations metrics are not available right now. Refresh the workspace or return after the backend is reachable.
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  const data: Record<string, unknown> = (analytics as unknown as Record<string, unknown>) || (dashboard as unknown as Record<string, unknown>) || {};
  const overview: Record<string, unknown> = (data.overview as Record<string, unknown>) || (data.summary as Record<string, unknown>) || {};
  
  const stats = {
    total_reports: Number(overview.total_reports || 0),
    reports_period: Number(
      analytics
        ? overview.reports_last_30d || overview.reports_last_7d || overview.reports_last_24h || 0
        : overview.reports_this_week || 0
    ),
    avg_quality: Number(overview.avg_quality_score || overview.average_quality_score || 0),
    success_rate: Number(overview.success_rate || 0.95),
  };
  const recentActivity = Array.isArray(data.recent_activity)
    ? (data.recent_activity as Record<string, unknown>[])
    : [];
  const threatDistribution = typeof data.threat_distribution === 'object' && data.threat_distribution !== null
    ? (data.threat_distribution as Record<string, unknown>)
    : {};
  const threatEntries = Object.entries(threatDistribution).slice(0, 5);
  const maxThreatCount = Math.max(1, ...Object.values(threatDistribution).map(v => Number(v || 0)));
  const shownRecentActivity = recentActivity.slice(0, 5);

  return (
    <AuthGuard>
      <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SurfaceHeader
          eyebrow="Operations metrics"
          title="Intelligence operations review"
          description="Review report volume, quality signals, and threat distribution before planning the next intelligence pass."
          action={
            <div className="w-full min-w-0 sm:max-w-xs">
            <Select
              label="Review window"
              options={timeRangeOptions}
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="border-slate-300 focus:border-slate-800 focus:ring-slate-800"
            />
            </div>
          }
        />

        <div className="mb-4 flex items-center justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Operations signal strip</p>
            <p className="mt-1 text-sm text-slate-500">Core signals for report output, confidence, cadence, and metric source.</p>
          </div>
        </div>

        <div className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Card className="border-slate-200 shadow-sm">
            <CardContent className="py-5">
              <div className="flex min-w-0 items-center">
                <div className="flex-shrink-0">
                  <DocumentTextIcon className="h-7 w-7 text-slate-700" />
                </div>
                <div className="ml-4 min-w-0">
                  <p className="text-sm font-medium text-slate-500">Saved intelligence</p>
                  <p className="text-2xl font-semibold text-slate-950">{stats.total_reports}</p>
                  <p className="text-sm text-slate-600">
                    {stats.reports_period} in the selected window
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardContent className="py-5">
              <div className="flex min-w-0 items-center">
                <div className="flex-shrink-0">
                  <ArrowTrendingUpIcon className="h-7 w-7 text-emerald-700" />
                </div>
                <div className="ml-4 min-w-0">
                  <p className="text-sm font-medium text-slate-500">Average confidence</p>
                  <p className="text-2xl font-semibold text-slate-950">{stats.avg_quality.toFixed(1)}</p>
                  <p className="text-sm text-slate-600">
                    {((stats.success_rate || 0) * 100).toFixed(1)}% completed without retry
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardContent className="py-5">
              <div className="flex min-w-0 items-center">
                <div className="flex-shrink-0">
                  <ClockIcon className="h-7 w-7 text-amber-700" />
                </div>
                <div className="ml-4 min-w-0">
                  <p className="text-sm font-medium text-slate-500">Activity cadence</p>
                  <p className="text-2xl font-semibold text-slate-950">{shownRecentActivity.length}</p>
                  <p className="text-sm text-slate-600">recent report events shown</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardContent className="py-5">
              <div className="flex min-w-0 items-center">
                <div className="flex-shrink-0">
                  <ShieldCheckIcon className="h-7 w-7 text-indigo-700" />
                </div>
                <div className="ml-4 min-w-0">
                  <p className="text-sm font-medium text-slate-500">Metric readiness</p>
                  <p className="text-2xl font-semibold text-slate-950">
                    {analytics ? 'Primary' : 'Fallback'}
                  </p>
                  <p className="text-sm text-slate-600">source for this review</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <p className="text-xs font-semibold uppercase tracking-wide text-cyan-700">Review timeline</p>
              <CardTitle className="mt-1 text-base text-slate-950">Recent report activity</CardTitle>
            </CardHeader>
            <CardContent>
              {recentActivity.length > 0 ? (
                <div className="space-y-4">
                  {shownRecentActivity.map((activity: Record<string, unknown>, index: number) => (
                    <div key={index} className="flex min-w-0 items-center justify-between gap-3 border-b border-slate-100 py-2 last:border-b-0">
                      <div className="min-w-0">
                        <p className="truncate font-medium text-slate-950">{(activity?.tool_name as string) || `Report ${index + 1}`}</p>
                        <p className="text-sm text-slate-500">
                          {activity?.created_at ? formatRelativeTime(activity.created_at as string) : 'Recently'}
                        </p>
                      </div>
                      <Badge variant="success">
                        Confidence: {Number(activity?.quality_score || 4.0).toFixed(1)}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-slate-400" />
                  <p className="text-slate-500">No recent report activity in this window</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Threat coverage map</p>
              <CardTitle className="mt-1 text-base text-slate-950">Threat distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {threatEntries.length > 0 ? (
                <div className="space-y-4">
                  {threatEntries.map(([type, count]: [string, unknown]) => {
                    const countNum = Number(count || 0);
                    const percentage = Math.min((countNum / maxThreatCount * 100), 100);
                    
                    return (
                      <div key={type} className="flex min-w-0 items-center justify-between gap-3">
                        <span className="min-w-0 truncate text-sm font-medium capitalize text-slate-700">
                          {type.replace(/_/g, ' ')}
                        </span>
                        <div className="flex flex-shrink-0 items-center">
                          <div className="mr-3 h-2 w-24 rounded-full bg-slate-200">
                            <div 
                              className="h-2 rounded-full bg-slate-800"
                              style={{ width: `${percentage}%` }}
                            ></div>
                          </div>
                          <span className="w-8 text-right text-sm text-slate-500">{countNum}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-8">
                  <ChartBarIcon className="mx-auto mb-4 h-12 w-12 text-slate-400" />
                  <p className="text-slate-500">Coverage appears after reports classify threat patterns</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
    </AuthGuard>
  );
}
