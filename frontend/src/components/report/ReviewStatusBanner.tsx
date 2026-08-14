import type { ReviewStatus } from '@/lib/api-contracts';
import {
  getReviewStatusClasses,
  getReviewStatusDescription,
  getReviewStatusLabel,
} from '@/lib/report-status';

type ReviewStatusBannerProps = {
  status: ReviewStatus;
  retryPending?: boolean;
  retryDisabled?: boolean;
  retryError?: boolean;
  onRetry?: () => void;
};

const secondaryButtonClass =
  'inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 transition-colors hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 disabled:pointer-events-none disabled:opacity-50';

export function ReviewStatusBanner({
  status,
  retryPending = false,
  retryDisabled = false,
  retryError = false,
  onRetry,
}: ReviewStatusBannerProps) {
  const active = status === 'evaluation_pending';
  const tone = status === 'reviewable'
    ? 'border-emerald-200 bg-emerald-50'
    : status === 'generation_failed'
      ? 'border-red-200 bg-red-50'
      : status === 'evaluation_pending' || status === 'generating'
        ? 'border-blue-200 bg-blue-50'
        : 'border-amber-200 bg-amber-50';

  return (
    <section
      data-contract="Report.ReviewStatus.v1"
      className={`mt-6 rounded-xl border px-5 py-4 ${tone}`}
      role={active ? 'status' : undefined}
      aria-live={active ? 'polite' : undefined}
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <span className={`inline-flex rounded-md px-2 py-1 text-sm font-medium ${getReviewStatusClasses(status)}`}>
            {getReviewStatusLabel(status)}
          </span>
          <p className="mt-2 text-sm leading-6 text-zinc-700">
            {getReviewStatusDescription(status)}
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
    </section>
  );
}
