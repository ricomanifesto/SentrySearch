import type { ReviewStatus } from './api-contracts';

export function getReviewStatusLabel(status: ReviewStatus): string {
  switch (status) {
    case 'reviewable': return 'Reviewable';
    case 'needs_attention': return 'Needs analyst review';
    case 'needs_evaluation': return 'Needs evaluation';
    case 'evaluation_pending': return 'Evaluation in progress';
    case 'generating': return 'Generating';
    case 'generation_failed': return 'Generation failed';
  }
}

export function getReviewStatusDescription(status: ReviewStatus): string {
  switch (status) {
    case 'reviewable': return 'Evaluation and source checks completed without a blocking readiness finding.';
    case 'needs_attention': return 'The report is saved, but its evaluation or evidence signals require analyst attention.';
    case 'needs_evaluation': return 'The narrative is preserved and can be evaluated again without repeating research.';
    case 'evaluation_pending': return 'The saved narrative is being evaluated; this page updates automatically.';
    case 'generating': return 'Research and synthesis are still running.';
    case 'generation_failed': return 'Generation did not produce a saved narrative.';
  }
}

export function getReviewStatusClasses(status: ReviewStatus): string {
  if (status === 'reviewable') return 'bg-[var(--bg-success)] text-[var(--text-success)]';
  if (status === 'generating' || status === 'evaluation_pending') {
    return 'bg-[var(--bg-accent)] text-[var(--text-accent)]';
  }
  if (status === 'generation_failed') return 'bg-[var(--bg-danger)] text-[var(--text-danger)]';
  return 'bg-[var(--border-warning)] text-[var(--text-primary)]';
}
