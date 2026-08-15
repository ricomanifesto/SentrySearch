import Link from 'next/link';
import { ArrowRightIcon } from '@heroicons/react/24/outline';

type WorkspaceHandoffProps = {
  href: '/auth/signup' | '/generate';
};

export function WorkspaceHandoff({ href }: WorkspaceHandoffProps) {
  return (
    <div className="flex flex-col gap-8 border-l-4 border-blue-600 pl-6 sm:flex-row sm:items-center sm:justify-between sm:pl-8">
      <div className="max-w-xl">
        <p className="text-sm font-medium text-blue-700">Analyst workspace</p>
        <h2 className="mt-2 text-2xl font-semibold tracking-tight text-zinc-950">
          Start with evidence attached
        </h2>
        <p className="mt-3 text-base leading-7 text-zinc-600">
          Generate a report, inspect each source, and keep the evidence beside the
          analyst decision.
        </p>
      </div>
      <Link
        href={href}
        className="group inline-flex h-11 shrink-0 items-center justify-center gap-2 self-start rounded-lg bg-zinc-950 px-6 text-base font-medium text-white transition-colors duration-150 hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 sm:self-auto"
      >
        Open workspace
        <ArrowRightIcon
          className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5"
          aria-hidden="true"
        />
      </Link>
    </div>
  );
}
