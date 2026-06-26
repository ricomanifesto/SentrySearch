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

type ActivityTrailRow = {
  id: string;
  label: string;
  detail: string;
  timestamp: string;
  severity: ActivityEvent['severity'];
  Icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  tone: string;
  metadataSummary?: string;
};

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

const getActivityTone = (type: string) => {
  switch (type) {
    case 'report_created': return 'bg-emerald-50 text-emerald-700';
    case 'report_viewed': return 'bg-cyan-50 text-cyan-700';
    case 'report_deleted': return 'bg-red-50 text-red-700';
    case 'export_generated': return 'bg-violet-50 text-violet-700';
    case 'user_login': return 'bg-indigo-50 text-indigo-700';
    case 'system_error': return 'bg-red-50 text-red-700';
    default: return 'bg-zinc-100 text-zinc-700';
  }
};

function summarizeActivityMetadata(metadata?: Record<string, unknown>) {
  if (!metadata) {
    return undefined;
  }

  if (typeof metadata.tool_name === 'string') {
    return metadata.tool_name;
  }

  if (typeof metadata.format === 'string' && typeof metadata.count === 'number') {
    return `${metadata.count} ${metadata.format.toUpperCase()} records`;
  }

  if (typeof metadata.source === 'string') {
    return `${metadata.source} source`;
  }

  return undefined;
}

function buildActivityTrailRows(activities: ActivityEvent[]): ActivityTrailRow[] {
  return activities.map((activity) => ({
    id: activity.id,
    label: activity.description,
    detail: activity.username ? `Recorded by ${activity.username}` : 'Workspace event',
    timestamp: formatRelativeTime(activity.created_at),
    severity: activity.severity,
    Icon: getActivityIcon(activity.type),
    tone: getActivityTone(activity.type),
    metadataSummary: summarizeActivityMetadata(activity.metadata),
  }));
}

interface ActivityFeedProps {
  userId?: string;
  limit?: number;
  showHeader?: boolean;
  compact?: boolean;
}

export function ActivityFeed({ userId, limit = 10, showHeader = true, compact = false }: ActivityFeedProps) {
  const { data: activities, isLoading, error } = useQuery({
    queryKey: ['activities', userId, limit],
    queryFn: () => api.getActivities(),
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
      description: 'Workspace session started',
      metadata: { session: 'active' },
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
      description: 'Source refresh is waiting on the retry window',
      metadata: { source: 'reports' },
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
  const activityTrailRows = buildActivityTrailRows(displayActivities as ActivityEvent[]);

  if (error) {
    return (
      <Card className="border-red-200 bg-red-50">
        <CardContent className="py-5 text-center">
          <ExclamationTriangleIcon className="mx-auto mb-2 h-8 w-8 text-red-500" />
          <p className="text-sm font-medium text-red-700">Activity trail is unavailable right now</p>
          <p className="mt-1 text-xs leading-5 text-red-600">
            Continue with saved reports while the workspace events reconnect.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-contract="Dashboard.ActivityTrail.v1" className="border-zinc-200 shadow-sm">
      {showHeader && (
        <CardHeader className="border-b border-zinc-100 pb-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-violet-700">Workspace event log</p>
          <CardTitle className="mt-1 flex items-center gap-2 text-base text-zinc-950">
            <ClockIcon className="h-5 w-5 text-zinc-500" />
            <span>Activity trail</span>
          </CardTitle>
          <p className="mt-2 text-xs leading-5 text-zinc-500">
            Recent report, export, and session events for the briefing review.
          </p>
        </CardHeader>
      )}
      <CardContent className={showHeader ? '' : 'pt-6'}>
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="flex items-start gap-3">
                  <div className="h-8 w-8 rounded-md bg-zinc-200"></div>
                  <div className="flex-1 space-y-2">
                    <div className="h-4 w-3/4 rounded bg-zinc-200"></div>
                    <div className="h-3 w-1/2 rounded bg-zinc-200"></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : activityTrailRows.length === 0 ? (
          <div className="py-8 text-center text-zinc-500">
            <ClockIcon className="mx-auto mb-4 h-12 w-12 text-zinc-400" />
            <p>Activity appears after reports are generated, opened, exported, or retired</p>
          </div>
        ) : (
          <div className="space-y-3">
            {activityTrailRows.slice(0, limit).map((activity) => {
              const Icon = activity.Icon;

              return (
                <div key={activity.id} className="flex min-w-0 items-start gap-3 rounded-md border border-zinc-100 bg-white px-3 py-3">
                  <div className={`flex-shrink-0 rounded-md p-2 ${activity.tone}`}>
                    <Icon aria-hidden="true" className="h-4 w-4" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <p className={`text-sm font-medium text-zinc-950 ${compact ? 'truncate' : ''}`}>
                          {activity.label}
                        </p>

                        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
                          <span className="text-xs text-zinc-500">{activity.detail}</span>
                          <span className="text-xs text-zinc-400" aria-hidden="true">&middot;</span>
                          <span className="text-xs text-zinc-500">{activity.timestamp}</span>
                          {!compact && activity.metadataSummary ? (
                            <>
                              <span className="text-xs text-zinc-400" aria-hidden="true">&middot;</span>
                              <span className="text-xs font-medium text-zinc-600">{activity.metadataSummary}</span>
                            </>
                          ) : null}
                        </div>
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
        
        {activityTrailRows.length > limit && (
          <div className="mt-4 text-center">
            <button className="text-sm font-medium text-zinc-700 hover:text-zinc-950">
              Review full activity trail
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default ActivityFeed;
