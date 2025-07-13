/**
 * Analytics Dashboard
 * 
 * Comprehensive analytics interface showing report generation metrics,
 * threat intelligence trends, and system performance data.
 */

'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarIcon,
  ClockIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  ArrowTrendingUpIcon,
  CpuChipIcon,
  CalendarDaysIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

interface AnalyticsData {
  overview: {
    total_reports: number;
    reports_last_24h: number;
    reports_last_7d: number;
    reports_last_30d: number;
    avg_quality_score: number;
    avg_processing_time_ms: number;
    most_common_threat_type: string;
    success_rate: number;
  };
  trends: {
    daily_reports: Array<{ date: string; count: number }>;
    threat_type_distribution: Array<{ threat_type: string; count: number; percentage: number }>;
    quality_score_distribution: Array<{ range: string; count: number; percentage: number }>;
    processing_time_trends: Array<{ date: string; avg_time_ms: number }>;
  };
  recent_activity: Array<{
    id: string;
    tool_name: string;
    quality_score: number;
    processing_time_ms: number;
    created_at: string;
    threat_type?: string;
  }>;
}

const timeRangeOptions = [
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: '90d', label: 'Last 90 Days' },
];

export default function AnalyticsPage() {
  const [timeRange, setTimeRange] = useState('30d');

  // Fetch analytics data
  const { data: analytics, isLoading, error } = useQuery({
    queryKey: ['analytics', timeRange],
    queryFn: () => api.getAnalytics(timeRange),
  });

  if (isLoading) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/3 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-64 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <Card className="border-red-200 bg-red-50">
          <CardContent className="text-center py-8">
            <ExclamationTriangleIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-lg font-semibold text-red-800 mb-2">Analytics Unavailable</h2>
            <p className="text-red-600">Failed to load analytics data. Please try again later.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const overview = analytics?.overview || {};

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Analytics</h1>
          <p className="mt-2 text-gray-600">
            System insights and threat intelligence metrics
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <Select
            options={timeRangeOptions}
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="w-40"
          />
        </div>
      </div>

      {/* Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardContent className="py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <DocumentTextIcon className="h-8 w-8 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total Reports</p>
                <p className="text-2xl font-bold text-gray-900">{overview.total_reports || 0}</p>
                <p className="text-sm text-gray-600">
                  {overview.reports_last_24h || 0} in last 24h
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUpIcon className="h-8 w-8 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Avg Quality Score</p>
                <p className="text-2xl font-bold text-gray-900">
                  {overview.avg_quality_score?.toFixed(1) || '0.0'}
                </p>
                <p className="text-sm text-gray-600">
                  {overview.success_rate ? `${(overview.success_rate * 100).toFixed(1)}% success rate` : 'No data'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ClockIcon className="h-8 w-8 text-orange-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Avg Processing Time</p>
                <p className="text-2xl font-bold text-gray-900">
                  {overview.avg_processing_time_ms ? `${Math.round(overview.avg_processing_time_ms / 1000)}s` : '0s'}
                </p>
                <p className="text-sm text-gray-600">Generation speed</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Top Threat Type</p>
                <p className="text-lg font-bold text-gray-900">
                  {overview.most_common_threat_type || 'Unknown'}
                </p>
                <p className="text-sm text-gray-600">Most analyzed</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts and Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Daily Reports Trend */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ChartBarIcon className="h-5 w-5" />
              <span>Daily Report Generation</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analytics?.trends?.daily_reports?.length > 0 ? (
              <div className="space-y-4">
                {analytics.trends.daily_reports.slice(-7).map((item, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">{formatDate(item.date)}</span>
                    <div className="flex items-center space-x-2">
                      <div className="bg-blue-100 rounded-full px-3 py-1">
                        <span className="text-sm font-medium text-blue-800">{item.count}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <ChartBarIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <p>No trend data available</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Threat Type Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ExclamationTriangleIcon className="h-5 w-5" />
              <span>Threat Type Distribution</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analytics?.trends?.threat_type_distribution?.length > 0 ? (
              <div className="space-y-3">
                {analytics.trends.threat_type_distribution.slice(0, 5).map((item, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <span className="text-sm text-gray-700 capitalize">
                      {item.threat_type.replace(/_/g, ' ')}
                    </span>
                    <div className="flex items-center space-x-2">
                      <div className="w-20 bg-gray-200 rounded-full h-2">
                        <div 
                          className="bg-blue-600 h-2 rounded-full" 
                          style={{ width: `${item.percentage}%` }}
                        ></div>
                      </div>
                      <span className="text-sm font-medium text-gray-900 w-8 text-right">
                        {item.count}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <ExclamationTriangleIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <p>No distribution data available</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quality Score Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ArrowTrendingUpIcon className="h-5 w-5" />
              <span>Quality Score Distribution</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analytics?.trends?.quality_score_distribution?.length > 0 ? (
              <div className="space-y-3">
                {analytics.trends.quality_score_distribution.map((item, index) => {
                  const variant = 
                    item.range.includes('4') ? 'success' :
                    item.range.includes('3') ? 'info' :
                    item.range.includes('2') ? 'warning' : 'error';
                  
                  return (
                    <div key={index} className="flex items-center justify-between">
                      <Badge variant={variant} size="sm">{item.range}</Badge>
                      <div className="flex items-center space-x-2">
                        <div className="w-20 bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-green-600 h-2 rounded-full" 
                            style={{ width: `${item.percentage}%` }}
                          ></div>
                        </div>
                        <span className="text-sm font-medium text-gray-900 w-8 text-right">
                          {item.count}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <ArrowTrendingUpIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <p>No quality data available</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <CalendarDaysIcon className="h-5 w-5" />
              <span>Recent Activity</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analytics?.recent_activity?.length > 0 ? (
              <div className="space-y-4">
                {analytics.recent_activity.slice(0, 5).map((activity) => {
                  const qualityVariant = 
                    activity.quality_score >= 4.0 ? 'success' :
                    activity.quality_score >= 3.0 ? 'info' :
                    activity.quality_score >= 2.0 ? 'warning' : 'error';

                  return (
                    <div key={activity.id} className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {activity.tool_name}
                        </p>
                        <p className="text-xs text-gray-500">
                          {formatRelativeTime(activity.created_at)}
                        </p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={qualityVariant} size="sm">
                          {activity.quality_score.toFixed(1)}
                        </Badge>
                        {activity.processing_time_ms && (
                          <span className="text-xs text-gray-500">
                            {Math.round(activity.processing_time_ms / 1000)}s
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <CalendarDaysIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                <p>No recent activity</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* System Health */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <CpuChipIcon className="h-5 w-5" />
            <span>System Health</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600 mb-1">
                {overview.success_rate ? `${(overview.success_rate * 100).toFixed(1)}%` : '0%'}
              </div>
              <p className="text-sm text-gray-600">Success Rate</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600 mb-1">
                {overview.avg_processing_time_ms ? `${Math.round(overview.avg_processing_time_ms / 1000)}s` : '0s'}
              </div>
              <p className="text-sm text-gray-600">Avg Response Time</p>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600 mb-1">
                {overview.reports_last_24h || 0}
              </div>
              <p className="text-sm text-gray-600">Reports Today</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}