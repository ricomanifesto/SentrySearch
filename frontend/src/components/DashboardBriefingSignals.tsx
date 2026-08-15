import type { AnalyticsDashboard } from '@/lib/api-contracts';

type DashboardBriefingSignalsProps = {
  analytics?: AnalyticsDashboard;
  isLoading: boolean;
};

export function DashboardBriefingSignals({
  analytics,
  isLoading,
}: DashboardBriefingSignalsProps) {
  if (isLoading) {
    return (
      <dl
        data-contract="Dashboard.BriefingSignalStrip.v1"
        className="mt-10 grid gap-6 border-y border-zinc-200 py-6 sm:grid-cols-3"
        role="status"
        aria-label="Loading workspace briefing"
      >
        {[0, 1, 2].map((index) => (
          <div key={index} aria-hidden="true">
            <div className="h-4 w-28 animate-pulse rounded bg-zinc-100" />
            <div className="mt-3 h-8 w-16 animate-pulse rounded bg-zinc-100" />
            <div className="mt-2 h-4 w-40 animate-pulse rounded bg-zinc-100" />
          </div>
        ))}
      </dl>
    );
  }

  const signals = [
    {
      label: 'Intelligence library',
      value: analytics?.summary.total_reports ?? 0,
      detail: 'Saved reports in this workspace',
    },
    {
      label: 'Completed this week',
      value: analytics?.summary.completed_reports_this_week ?? 0,
      detail: analytics
        ? `${analytics.summary.runs_this_week} runs started · ${analytics.summary.failed_reports_this_week} failed`
        : 'Completed report records',
    },
    {
      label: 'Content quality',
      value: analytics?.summary.avg_quality_score == null
        ? '—'
        : analytics.summary.avg_quality_score.toFixed(2),
      detail: analytics?.summary.avg_quality_score == null
        ? 'No scored reports yet'
        : `${analytics.summary.scored_reports} scored · ${analytics.summary.unresolved_reports} unresolved`,
    },
  ];

  return (
    <dl
      data-contract="Dashboard.BriefingSignalStrip.v1"
      className="mt-10 grid gap-6 border-y border-zinc-200 py-6 sm:grid-cols-3"
    >
      {signals.map((signal) => (
        <div key={signal.label}>
          <dt className="text-sm text-zinc-500">{signal.label}</dt>
          <dd className="mt-1 text-2xl font-semibold text-zinc-950">{signal.value}</dd>
          <dd className="mt-0.5 text-sm text-zinc-500">{signal.detail}</dd>
        </div>
      ))}
    </dl>
  );
}
