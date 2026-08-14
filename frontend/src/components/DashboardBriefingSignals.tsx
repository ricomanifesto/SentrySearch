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
        className="mt-8 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-3"
        role="status"
        aria-label="Loading workspace briefing"
      >
        {[0, 1, 2].map((index) => (
          <div key={index} className="bg-white px-5 py-5" aria-hidden="true">
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
      label: 'Briefed this week',
      value: analytics?.summary.reports_this_week ?? 0,
      detail: 'New intelligence generated',
    },
    {
      label: 'Report quality',
      value: analytics?.summary.avg_quality_score == null
        ? '—'
        : analytics.summary.avg_quality_score.toFixed(2),
      detail: analytics?.summary.avg_quality_score == null
        ? 'No scored reports yet'
        : `${analytics.summary.scored_reports} of ${analytics.summary.total_reports} reports scored`,
    },
  ];

  return (
    <dl
      data-contract="Dashboard.BriefingSignalStrip.v1"
      className="mt-8 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-3"
    >
      {signals.map((signal) => (
        <div key={signal.label} className="bg-white px-5 py-5">
          <dt className="text-sm text-zinc-500">{signal.label}</dt>
          <dd className="mt-1 text-2xl font-semibold text-zinc-950">{signal.value}</dd>
          <dd className="mt-0.5 text-sm text-zinc-500">{signal.detail}</dd>
        </div>
      ))}
    </dl>
  );
}
