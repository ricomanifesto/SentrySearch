import type { AnalystDisposition } from './api-contracts';

export function getAnalystDispositionLabel(disposition: AnalystDisposition): string {
  switch (disposition) {
    case 'accepted':
      return 'Accepted for reuse';
    case 'needs_revision':
      return 'Needs revision';
    case 'rejected':
      return 'Rejected';
    case 'unreviewed':
      return 'Awaiting analyst judgment';
  }
}

export function getAnalystDispositionClasses(disposition: AnalystDisposition): string {
  switch (disposition) {
    case 'accepted':
      return 'bg-green-100 text-green-800';
    case 'needs_revision':
      return 'bg-amber-50 text-amber-800';
    case 'rejected':
      return 'bg-red-50 text-red-800';
    case 'unreviewed':
      return 'bg-zinc-100 text-zinc-700';
  }
}
