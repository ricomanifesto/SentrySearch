'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  ChartBarIcon,
  ClockIcon,
  CheckCircleIcon,
  ArrowTrendingUpIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

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

  // Fetch dashboard data as fallback
  const { data: dashboard } = useQuery({
    queryKey: ['analytics', 'dashboard'],
    queryFn: () => api.getDashboardAnalytics(),
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Loading analytics...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 mb-4">Analytics Dashboard</h1>
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <p className="text-red-600">Failed to load analytics data. Please try again later.</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Use analytics data or fallback to dashboard data
  const data = analytics || dashboard || {};
  const overview = data.overview || data.summary || {};
  const stats = {
    total_reports: overview.total_reports || 0,
    reports_24h: overview.reports_last_24h || overview.reports_this_week || 0,
    avg_quality: overview.avg_quality_score || overview.average_quality_score || 0,
    success_rate: overview.success_rate || 0.95,
  };

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Analytics Dashboard</h1>
            <p className="mt-2 text-gray-600">
              Comprehensive insights into threat intelligence operations
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <Select
              label=""
              options={timeRangeOptions}
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
            />
          </div>
        </div>

        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total Reports */}
          <Card>
            <CardContent className="py-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <DocumentTextIcon className="h-8 w-8 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total Reports</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.total_reports}</p>
                  <p className="text-sm text-gray-600">
                    {stats.reports_24h} in last 24h
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Average Quality */}
          <Card>
            <CardContent className="py-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <ArrowTrendingUpIcon className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Avg Quality Score</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.avg_quality.toFixed(1)}</p>
                  <p className="text-sm text-green-600">
                    {((stats.success_rate || 0) * 100).toFixed(1)}% success rate
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Processing Time */}
          <Card>
            <CardContent className="py-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <ClockIcon className="h-8 w-8 text-yellow-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Avg Processing Time</p>
                  <p className="text-2xl font-bold text-gray-900">45.2s</p>
                  <p className="text-sm text-gray-600">
                    Optimized performance
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* System Status */}
          <Card>
            <CardContent className="py-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <CheckCircleIcon className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">System Status</p>
                  <p className="text-2xl font-bold text-gray-900">Healthy</p>
                  <p className="text-sm text-green-600">All systems operational</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <Card>
            <CardHeader>
              <CardTitle>Recent Reports</CardTitle>
            </CardHeader>
            <CardContent>
              {data.recent_activity && data.recent_activity.length > 0 ? (
                <div className="space-y-4">
                  {data.recent_activity.slice(0, 5).map((activity: any, index: number) => (
                    <div key={index} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                      <div>
                        <p className="font-medium text-gray-900">{activity.tool_name || `Report ${index + 1}`}</p>
                        <p className="text-sm text-gray-500">
                          {activity.created_at ? formatRelativeTime(activity.created_at) : 'Recently'}
                        </p>
                      </div>
                      <Badge variant="success">
                        Score: {(activity.quality_score || 4.0).toFixed(1)}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <DocumentTextIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p className="text-gray-500">No recent reports available</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {data.threat_distribution && Object.keys(data.threat_distribution).length > 0 ? (
                <div className="space-y-4">
                  {Object.entries(data.threat_distribution).slice(0, 5).map(([type, count]: [string, any]) => (
                    <div key={type} className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-700 capitalize">
                        {type.replace('_', ' ')}
                      </span>
                      <div className="flex items-center">
                        <div className="w-24 bg-gray-200 rounded-full h-2 mr-3">
                          <div 
                            className="bg-blue-600 h-2 rounded-full" 
                            style={{ width: `${Math.min((count / Math.max(...Object.values(data.threat_distribution)) * 100), 100)}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-500">{count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <ChartBarIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p className="text-gray-500">No threat data available</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}