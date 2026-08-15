import type { AnalystDisposition, ReviewStatus } from '@/lib/api-contracts';
import {
  getAnalystDispositionClasses,
  getAnalystDispositionLabel,
} from '@/lib/analyst-disposition';
import {
  getReviewStatusClasses,
  getReviewStatusDescription,
  getReviewStatusLabel,
} from '@/lib/report-status';
import type { ReviewAttentionSummary } from '@/lib/review-attention';

type ReviewStatusBannerProps = {
  status: ReviewStatus;
  retryPending?: boolean;
  retryDisabled?: boolean;
  retryError?: boolean;
  onRetry?: () => void;
  attention?: ReviewAttentionSummary | null;
  analystDisposition?: AnalystDisposition;
  acceptanceEligible?: boolean;
};

const secondaryButtonClass =
  'inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 disabled:pointer-events-none disabled:opacity-50';

export function ReviewStatusBanner({
  status,
  retryPending = false,
  retryDisabled = false,
  retryError = false,
  onRetry,
  attention,
  analystDisposition = 'unreviewed',
  acceptanceEligible = false,
}: ReviewStatusBannerProps) {
  const active = status === 'evaluation_pending';
  const dispositionOwnsReadiness = analystDisposition !== 'unreviewed'
    && (analystDisposition !== 'accepted' || acceptanceEligible)
    && (status === 'reviewable' || status === 'needs_attention');
  const tone = analystDisposition === 'accepted' && dispositionOwnsReadiness
    ? 'border-[var(--border-success)] bg-[var(--bg-success)]'
    : analystDisposition === 'rejected' && dispositionOwnsReadiness
      ? 'border-[var(--border-danger)] bg-[var(--bg-danger)]'
      : dispositionOwnsReadiness
        ? 'border-[var(--border-warning)] bg-[var(--bg-warning)]'
        : status === 'reviewable'
          ? 'border-[var(--border-success)] bg-[var(--bg-success)]'
          : status === 'generation_failed'
      ? 'border-[var(--border-danger)] bg-[var(--bg-danger)]'
      : status === 'evaluation_pending' || status === 'generating'
        ? 'border-[var(--accent)] bg-[var(--bg-accent)]'
        : 'border-[var(--border-warning)] bg-[var(--bg-warning)]';
  const label = dispositionOwnsReadiness
    ? getAnalystDispositionLabel(analystDisposition)
    : getReviewStatusLabel(status);
  const labelClasses = dispositionOwnsReadiness
    ? getAnalystDispositionClasses(analystDisposition)
    : getReviewStatusClasses(status);
  const description = dispositionOwnsReadiness
    ? analystDisposition === 'accepted'
      ? 'An analyst accepted this evaluation vintage for reuse.'
      : analystDisposition === 'needs_revision'
        ? 'An analyst kept this evaluation vintage in unresolved work.'
        : 'An analyst marked this evaluation vintage unsuitable for operational use.'
    : getReviewStatusDescription(status);

  return (
    <section
      data-contract="Report.ReviewStatus.v1"
      className={`mt-6 rounded-xl border px-5 py-4 ${tone}`}
      role={active ? 'status' : undefined}
      aria-live={active ? 'polite' : undefined}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-medium text-zinc-900">Operational readiness</p>
          <span className={`mt-2 inline-flex rounded-md px-2 py-1 text-sm font-medium ${labelClasses}`}>
            {label}
          </span>
          <p className="mt-2 text-sm leading-6 text-zinc-700">
            {description}
          </p>
        </div>
        {status === 'needs_evaluation' ? (
          <button
            type="button"
            onClick={onRetry}
            disabled={retryDisabled || retryPending}
            className={`${secondaryButtonClass} shrink-0`}
          >
            {retryPending ? 'Starting evaluation…' : 'Retry evaluation'}
          </button>
        ) : null}
      </div>
      {retryError ? (
        <p className="mt-3 text-sm text-red-700" role="alert">
          Evaluation could not be restarted. The saved narrative has not been removed.
        </p>
      ) : null}
      {status === 'needs_attention' && attention ? (
        <div className="mt-4 border-t border-[var(--border-warning)] pt-4">
          <p className="text-sm font-medium text-[var(--text-warning)]">{attention.headline}</p>
          {attention.evidenceFindings.length > 0 ? (
            <div className="mt-3">
              <p className="text-sm font-medium text-zinc-900">Evidence blockers</p>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm leading-6 text-zinc-700">
                {attention.evidenceFindings.map((finding) => <li key={finding}>{finding}</li>)}
              </ul>
            </div>
          ) : null}
          {attention.conflicts.length > 0 ? (
            <div className="mt-3">
              <p className="text-sm font-medium text-zinc-900">Conflicts to resolve</p>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm leading-6 text-zinc-700">
                {attention.conflicts.map((conflict) => <li key={conflict}>{conflict}</li>)}
              </ul>
            </div>
          ) : null}
          {attention.recommendations.length > 0 ? (
            <div className="mt-3">
              <p className="text-sm font-medium text-zinc-900">Recommended next checks</p>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm leading-6 text-zinc-700">
                {attention.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
