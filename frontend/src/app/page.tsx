'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ArrowRightIcon } from '@heroicons/react/24/outline';

import { useAuth } from '@/contexts/AuthContext';

const steps = [
  {
    n: '01',
    title: 'Name a target',
    body: 'A malware family, attack tool, or exposed technology that needs a source-backed profile.',
  },
  {
    n: '02',
    title: 'Research and synthesis',
    body: 'Sources are gathered and analyzed into a structured profile, with the evidence kept alongside each section.',
  },
  {
    n: '03',
    title: 'Review the report',
    body: 'Read the narrative, detection guidance, and mitigations, then save it to your review queue.',
  },
];

const sampleFindings = [
  {
    body: 'Modular backdoor linked to state-aligned espionage, typically delivered through DLL side-loading.',
    cite: 'source · vendor threat report',
  },
  {
    body: 'Detection: signed but anomalous DLLs loaded by otherwise trusted host processes.',
    cite: 'guidance · detection',
  },
];

export default function Landing() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) {
      router.replace('/dashboard');
    }
  }, [user, loading, router]);

  return (
    <main data-surface="landing" className="overflow-x-hidden bg-[var(--surface-0)]">
      <section className="mx-auto max-w-5xl px-6 pb-24 pt-24 lg:px-8">
        <div className="grid items-center gap-14 lg:grid-cols-[minmax(0,1fr)_minmax(0,26rem)]">
          <div className="fade-up">
            <p className="text-sm font-medium text-blue-700">Source-backed threat intelligence</p>
            <h1 className="mt-4 text-balance text-4xl font-semibold leading-[1.08] tracking-tight text-zinc-950 sm:text-5xl">
              Threat reports you can actually defend
            </h1>
            <p className="mt-5 max-w-md text-lg leading-8 text-zinc-600">
              SentrySearch researches malware, attack tools, and exposed
              technologies, then assembles a structured report with detection
              guidance and the evidence behind every claim.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Link
                href="/auth/signup"
                className="group inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-6 text-base font-medium text-white transition-colors duration-150 hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2"
              >
                Get started
                <ArrowRightIcon className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5" />
              </Link>
              <Link
                href="/auth/signin"
                className="inline-flex h-11 items-center justify-center rounded-lg border border-zinc-300 bg-white px-6 text-base font-medium text-zinc-800 transition-colors duration-150 hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
              >
                Sign in
              </Link>
            </div>
            <p className="mt-4 text-base text-zinc-500">
              Or{' '}
              <Link
                href="/sample"
                className="font-medium text-blue-700 underline-offset-4 hover:underline"
              >
                see a sample report
              </Link>{' '}
              — no account needed.
            </p>
          </div>

          <Link
            href="/sample"
            className="fade-up fade-up-2 group block rounded-xl border border-zinc-200 bg-white transition-colors duration-150 hover:border-zinc-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2"
          >
            <div className="flex items-center justify-between gap-3 border-b border-zinc-200 px-5 py-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-base font-medium text-zinc-950">ShadowPad</span>
                <span className="rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">
                  High confidence
                </span>
              </div>
              <span className="text-sm text-zinc-400">Example report</span>
            </div>
            <div className="divide-y divide-zinc-100">
              {sampleFindings.map((f) => (
                <div key={f.cite} className="px-5 py-4">
                  <p className="text-base leading-7 text-zinc-800">{f.body}</p>
                  <p className="mt-2 font-mono text-sm text-zinc-500">{f.cite}</p>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-1.5 border-t border-zinc-100 px-5 py-3 text-base font-medium text-blue-700">
              View full sample report
              <ArrowRightIcon className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5" />
            </div>
          </Link>
        </div>
      </section>

      <section className="border-y border-zinc-200 bg-white">
        <div className="mx-auto max-w-5xl px-6 py-20 lg:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">How it works</p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight text-zinc-950">
              From a name to a report you can defend
            </h2>
          </div>

          <ol className="mt-10 grid gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-3">
            {steps.map((step) => (
              <li key={step.n} className="bg-white p-6">
                <span className="font-mono text-base font-medium text-blue-700">{step.n}</span>
                <h3 className="mt-3 text-base font-semibold text-zinc-950">{step.title}</h3>
                <p className="mt-2 text-base leading-7 text-zinc-600">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-24 lg:px-8">
        <div className="rounded-2xl border border-zinc-200 bg-zinc-950 px-6 py-14 text-center sm:px-12">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Generate your first report
          </h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-zinc-300">
            Create a workspace to run a report and keep your saved intelligence in
            one place.
          </p>
          <div className="mt-8 flex justify-center">
            <Link
              href="/auth/signup"
              className="group inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-white px-6 text-base font-medium text-zinc-950 transition-colors duration-150 hover:bg-zinc-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950"
            >
              Get started
              <ArrowRightIcon className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5" />
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t border-zinc-200">
        <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-3 px-6 py-8 text-base text-zinc-500 sm:flex-row lg:px-8">
          <p>SentrySearch</p>
          <p>Source-backed threat intelligence.</p>
        </div>
      </footer>
    </main>
  );
}
