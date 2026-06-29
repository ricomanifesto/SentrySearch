'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  UserIcon,
  ExclamationTriangleIcon,
  ArrowDownTrayIcon,
  PlusIcon,
  TrashIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';

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

const severityDotClass = (severity: string) => {
  switch (severity) {
    case 'success': return 'bg-green-500';
    case 'warning': return 'bg-amber-500';
    case 'error': return 'bg-red-500';
    case 'info':
    default: return 'bg-blue-500';
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
    refetchInterval: 30000,
  });

  // Only ever render real activity. Never fall back to fabricated events.
  const activityTrailRows = buildActivityTrailRows((activities as unknown as ActivityEvent[]) || []);

  if (error) {
    return (
      <section data-contract="Dashboard.ActivityTrail.v1" className="rounded-xl border border-red-200 bg-red-50 p-5">
        <h2 className="text-base font-semibold text-red-900">Activity trail</h2>
        <p className="mt-2 text-sm leading-6 text-red-700">
          Activity trail is unavailable right now. Continue with saved reports while the workspace events reconnect.
        </p>
      </section>
    );
  }

  return (
    <section data-contract="Dashboard.ActivityTrail.v1" className="min-w-0 rounded-xl border border-zinc-200 bg-white p-5">
      {showHeader && (
        <div>
          <h2 className="text-base font-semibold text-zinc-950">Activity trail</h2>
          <p className="mt-1 text-sm leading-6 text-zinc-500">
            Recent report, export, and session events for the briefing review.
          </p>
        </div>
      )}
      <div className={showHeader ? 'mt-4' : ''}>
        {isLoading ? (
          <div className="space-y-3" role="status" aria-label="Loading activity trail">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-12 animate-pulse rounded-lg bg-zinc-100" />
            ))}
          </div>
        ) : activityTrailRows.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-300 px-4 py-8 text-center">
            <p className="text-sm text-zinc-500">
              Activity appears after reports are generated, opened, exported, or retired.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {activityTrailRows.slice(0, limit).map((activity) => {
              const Icon = activity.Icon;
              return (
                <div key={activity.id} className="flex min-w-0 items-start gap-3 rounded-lg border border-zinc-100 px-3 py-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-100 text-zinc-600">
                    <Icon aria-hidden="true" className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className={`text-sm font-medium text-zinc-950 ${compact ? 'truncate' : ''}`}>{activity.label}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-zinc-500">
                      <span>{activity.detail}</span>
                      <span aria-hidden="true">&middot;</span>
                      <span>{activity.timestamp}</span>
                      {!compact && activity.metadataSummary ? (
                        <>
                          <span aria-hidden="true">&middot;</span>
                          <span className="font-medium text-zinc-600">{activity.metadataSummary}</span>
                        </>
                      ) : null}
                    </div>
                  </div>
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${severityDotClass(activity.severity)}`}
                    aria-label={activity.severity}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}

export default ActivityFeed;
