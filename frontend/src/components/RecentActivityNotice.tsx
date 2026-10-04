import Link from 'next/link';

export function RecentActivityNotice() {
  return (
    <p role="status" className="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-900">
      Recent activity is incomplete.{' '}
      <Link href="/reports" className="font-medium underline underline-offset-4">Browse saved reports</Link>{' '}
      to continue through older records.
    </p>
  );
}
