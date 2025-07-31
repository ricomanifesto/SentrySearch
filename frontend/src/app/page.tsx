/**
 * SentrySearch Dashboard
 * 
 * Main dashboard showing analytics, recent reports, and quick actions.
 */

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

export default function Dashboard() {
  // Fetch dashboard analytics
  const { data: analytics, isLoading: analyticsLoading, error: analyticsError } = useQuery({
    queryKey: ['analytics', 'dashboard'],
    queryFn: () => api.getDashboardAnalytics(),
  });

  // Fetch recent reports
  const { data: recentReports, isLoading: reportsLoading } = useQuery({
    queryKey: ['reports', 'recent'],
    queryFn: () => api.listReports(1, 5),
  });

  // Quick stats cards
  const quickStats = [
    {
      title: 'Total Reports',
      value: analytics?.summary.total_reports ?? 0,
      icon: DocumentTextIcon,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
    },
    {
      title: 'This Week',
      value: analytics?.summary.reports_this_week ?? 0,
      icon: ChartBarIcon,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
    },
    {
      title: 'Avg Quality',
      value: analytics?.summary.avg_quality_score?.toFixed(1) ?? '0.0',
      icon: MagnifyingGlassIcon,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Overview of your threat intelligence operations
        </p>
      </div>

      {/* Quick Actions */}
      <div className="mb-8">
        <div className="flex flex-wrap gap-4">
          <Link href="/generate">
            <Button size="lg" className="flex items-center space-x-2">
              <PlusIcon className="h-5 w-5" />
              <span>Generate Report</span>
            </Button>
          </Link>
          <Link href="/search">
            <Button variant="outline" size="lg" className="flex items-center space-x-2">
              <MagnifyingGlassIcon className="h-5 w-5" />
              <span>Search Reports</span>
            </Button>
          </Link>
          <Link href="/reports">
            <Button variant="outline" size="lg" className="flex items-center space-x-2">
              <DocumentTextIcon className="h-5 w-5" />
              <span>Browse All</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="mb-8 grid grid-cols-1 gap-6 sm:grid-cols-3">
        {quickStats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.title}>
              <CardContent className="flex items-center">
                <div className={`rounded-lg p-3 ${stat.bgColor}`}>
                  <Icon className={`h-6 w-6 ${stat.color}`} />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">{stat.title}</p>
                  <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
        {/* Recent Reports */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Reports</CardTitle>
          </CardHeader>
          <CardContent>
            {reportsLoading ? (
              <div className="space-y-4">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="animate-pulse">
                    <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                    <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                  </div>
                ))}
              </div>
            ) : recentReports?.reports.length ? (
              <div className="space-y-4">
                {recentReports.reports.map((report) => {
                  const qualityScore = formatQualityScore(report.quality_score);
                  return (
                    <div key={report.id} className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <Link 
                          href={`/reports/${report.id}`}
                          className="text-sm font-medium text-gray-900 hover:text-blue-600 truncate block"
                        >
                          {report.tool_name}
                        </Link>
                        <p className="text-xs text-gray-500">
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
                <div className="pt-4 border-t">
                  <Link href="/reports">
                    <Button variant="ghost" size="sm" className="w-full">
                      View All Reports
                    </Button>
                  </Link>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500 mb-4">No reports yet</p>
                <Link href="/generate">
                  <Button size="sm">Generate Your First Report</Button>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Threat Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Threat Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {analyticsLoading ? (
              <div className="space-y-3">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="animate-pulse">
                    <div className="h-3 bg-gray-200 rounded w-full"></div>
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
                      <span className="text-sm text-gray-600 capitalize">
                        {threatType.replace(/_/g, ' ')}
                      </span>
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ 
                              width: `${Math.min(100, (count / Math.max(...Object.values(analytics.threat_distribution))) * 100)}%` 
                            }}
                          ></div>
                        </div>
                        <span className="text-sm font-medium text-gray-900 w-8 text-right">
                          {count}
                        </span>
                      </div>
                    </div>
                  ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <ChartBarIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No threat data available</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Activity Feed */}
        <ActivityFeed limit={6} compact={true} />
      </div>

      {/* Error State */}
      {analyticsError && (
        <Card variant="outlined" className="mt-8 border-red-200 bg-red-50">
          <CardContent>
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="h-5 w-5 text-red-400">⚠️</div>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">
                  Unable to load dashboard data
                </h3>
                <p className="text-sm text-red-600 mt-1">
                  Make sure the API server is running on {process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      </div>
    </div>
  );
}
