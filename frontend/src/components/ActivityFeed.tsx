/**
 * Activity Feed Component
 * 
 * Real-time activity tracking for user actions, system events,
 * and report generation activities.
 */

'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  UserIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ArrowDownTrayIcon,
  PlusIcon,
  TrashIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';

interface ActivityEvent {
  id: string;
  type: 'report_created' | 'report_viewed' | 'report_deleted' | 'export_generated' | 'user_login' | 'system_error';
  user_id?: string;
  username?: string;
  description: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  severity: 'info' | 'warning' | 'error' | 'success';
}

const getActivityIcon = (type: string) => {
  switch (type) {
    case 'report_created': return PlusIcon;
    case 'report_viewed': return EyeIcon;
    case 'report_deleted': return TrashIcon;
    case 'export_generated': return ArrowDownTrayIcon;
    case 'user_login': return UserIcon;
    case 'system_error': return ExclamationTriangleIcon;
    default: return DocumentTextIcon;
  }
};

const getSeverityVariant = (severity: string) => {
  switch (severity) {
    case 'success': return 'success';
    case 'warning': return 'warning';
    case 'error': return 'error';
    case 'info':
    default: return 'info';
  }
};

const getActivityColor = (type: string) => {
  switch (type) {
    case 'report_created': return 'text-green-600';
    case 'report_viewed': return 'text-blue-600';
    case 'report_deleted': return 'text-red-600';
    case 'export_generated': return 'text-purple-600';
    case 'user_login': return 'text-indigo-600';
    case 'system_error': return 'text-red-600';
    default: return 'text-gray-600';
  }
};

interface ActivityFeedProps {
  userId?: string;
  limit?: number;
  showHeader?: boolean;
  compact?: boolean;
}

export function ActivityFeed({ userId, limit = 10, showHeader = true, compact = false }: ActivityFeedProps) {
  const { data: activities, isLoading, error } = useQuery({
    queryKey: ['activities', userId, limit],
    queryFn: () => api.getActivities(userId, limit),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const mockActivities: ActivityEvent[] = [
    {
      id: '1',
      type: 'report_created',
      user_id: '1',
      username: 'admin',
      description: 'Generated threat intelligence report for ShadowPad',
      metadata: { report_id: 'rpt_123', tool_name: 'ShadowPad', quality_score: 4.2 },
      created_at: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
      severity: 'success'
    },
    {
      id: '2',
      type: 'export_generated',
      user_id: '2',
      username: 'analyst1',
      description: 'Exported 15 reports in JSON format',
      metadata: { format: 'json', count: 15 },
      created_at: new Date(Date.now() - 900000).toISOString(), // 15 minutes ago
      severity: 'info'
    },
    {
      id: '3',
      type: 'user_login',
      user_id: '1',
      username: 'admin',
      description: 'User logged in from 192.168.1.100',
      metadata: { ip_address: '192.168.1.100' },
      created_at: new Date(Date.now() - 1800000).toISOString(), // 30 minutes ago
      severity: 'info'
    },
    {
      id: '4',
      type: 'report_viewed',
      user_id: '2',
      username: 'analyst1',
      description: 'Viewed report: Cobalt Strike Analysis',
      metadata: { report_id: 'rpt_456', tool_name: 'Cobalt Strike' },
      created_at: new Date(Date.now() - 2700000).toISOString(), // 45 minutes ago
      severity: 'info'
    },
    {
      id: '5',
      type: 'system_error',
      description: 'API rate limit exceeded for IP 203.0.113.42',
      metadata: { ip_address: '203.0.113.42', endpoint: '/api/reports' },
      created_at: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
      severity: 'warning'
    },
    {
      id: '6',
      type: 'report_deleted',
      user_id: '1',
      username: 'admin',
      description: 'Deleted report: Outdated Malware Analysis',
      metadata: { report_id: 'rpt_789' },
      created_at: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
      severity: 'warning'
    }
  ];

  const displayActivities = activities || mockActivities;

  if (error) {
    return (
      <Card className="border-red-200 bg-red-50">
        <CardContent className="text-center py-4">
          <ExclamationTriangleIcon className="h-8 w-8 text-red-400 mx-auto mb-2" />
          <p className="text-red-600 text-sm">Failed to load activity feed</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      {showHeader && (
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <ClockIcon className="h-5 w-5" />
            <span>Recent Activity</span>
          </CardTitle>
        </CardHeader>
      )}
      <CardContent className={showHeader ? '' : 'pt-6'}>
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="flex items-start space-x-3">
                  <div className="h-8 w-8 bg-gray-200 rounded-full"></div>
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                    <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : displayActivities.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <ClockIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>No recent activity</p>
          </div>
        ) : (
          <div className="space-y-4">
            {displayActivities.slice(0, limit).map((activity) => {
              const Icon = getActivityIcon(activity.type);
              const iconColor = getActivityColor(activity.type);
              
              return (
                <div key={activity.id} className="flex items-start space-x-3">
                  <div className={`flex-shrink-0 p-2 rounded-full bg-gray-100 ${iconColor}`}>
                    <Icon className="h-4 w-4" />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className={`text-sm font-medium text-gray-900 ${compact ? 'truncate' : ''}`}>
                          {activity.description}
                        </p>
                        
                        <div className="flex items-center space-x-2 mt-1">
                          {activity.username && (
                            <span className="text-xs text-gray-600">
                              by {activity.username}
                            </span>
                          )}
                          <span className="text-xs text-gray-500">
                            {formatRelativeTime(activity.created_at)}
                          </span>
                        </div>
                        
                        {!compact && activity.metadata && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {Object.entries(activity.metadata).map(([key, value]) => (
                              <Badge key={key} variant="default" size="sm">
                                {key}: {String(value)}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      
                      <Badge variant={getSeverityVariant(activity.severity)} size="sm">
                        {activity.severity}
                      </Badge>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
        
        {displayActivities.length > limit && (
          <div className="text-center mt-4">
            <button className="text-sm text-blue-600 hover:text-blue-800">
              View all activity
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default ActivityFeed;