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

import { api, type ActivityEvent } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';

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
    detail: 'Workspace event',
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
  const activityTrailRows = buildActivityTrailRows(activities || []);

  if (error) {
    return (
      <section data-contract="Dashboard.ActivityTrail.v1" className="min-w-0 border-l-4 border-red-500 pl-5">
        <h2 className="text-base font-semibold text-red-900">Activity trail</h2>
        <p className="mt-2 text-sm leading-6 text-red-700">
          Activity trail is unavailable right now. Continue with saved reports while the workspace events reconnect.
        </p>
      </section>
    );
  }

  return (
    <section data-contract="Dashboard.ActivityTrail.v1" className="min-w-0 border-t border-zinc-200 pt-6">
      {showHeader && (
        <div>
          <h2 className="text-base font-semibold text-zinc-950">Activity trail</h2>
          <p className="mt-1 text-sm leading-6 text-zinc-500">
            Recently generated reports in this workspace.
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
              Activity appears after a report is generated.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-zinc-200">
            {activityTrailRows.slice(0, limit).map((activity) => {
              const Icon = activity.Icon;
              return (
                <div key={activity.id} className="flex min-w-0 items-start gap-3 py-3 first:pt-0">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-zinc-100 text-zinc-600">
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
