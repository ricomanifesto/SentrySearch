'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRightIcon, ArrowLeftIcon } from '@heroicons/react/24/outline';

const signals = [
  { label: 'Confidence', value: '4.3 / 5.0', detail: 'High confidence' },
  { label: 'Category', value: 'Backdoor', detail: 'Modular implant' },
  { label: 'Threat family', value: 'Espionage', detail: 'State-aligned tooling' },
  { label: 'Sources', value: '4 cited', detail: 'Linked to findings' },
];

type Section = {
  heading: string;
  paras: string[];
  cite: string;
};

const sections: Section[] = [
  {
    heading: 'Overview',
    paras: [
      'ShadowPad is a modular backdoor that has been used by multiple China-nexus intrusion sets since it first surfaced publicly in 2017. It is sold and shared privately rather than offered openly, and is typically reserved for targeted intrusions rather than commodity crime.',
      'It first came to broad attention through a software supply-chain compromise, where the implant was embedded in a legitimately signed product update before detection.',
    ],
    cite: 'source · vendor discovery report (2017)',
  },
  {
    heading: 'Capabilities',
    paras: [
      'The implant is plugin-based: a small loader decrypts and runs additional modules in memory, which keeps most functionality off disk and complicates static analysis. Observed modules cover remote shell access, file and registry operations, and credential collection.',
      'Command-and-control traffic is commonly tunneled over DNS and HTTP(S), and configuration is obfuscated to slow reverse engineering.',
    ],
    cite: 'source · malware analysis · structured extraction',
  },
  {
    heading: 'Detection guidance',
    paras: [
      'Watch for signed but anomalous DLLs loaded by otherwise trusted host processes — DLL side-loading is a recurring delivery path. Pair image-load telemetry with parent/child process lineage to surface trusted binaries loading unexpected modules.',
      'On the network, review long-lived or beaconing DNS and HTTP sessions to low-reputation infrastructure that do not match the host application’s normal behavior.',
    ],
    cite: 'guidance · detection',
  },
  {
    heading: 'Mitigations',
    paras: [
      'Constrain DLL search order and prefer signed-and-pinned module loading for sensitive applications. Enforce application allow-listing where feasible, and segment management interfaces so a single compromise does not yield broad lateral movement.',
      'Validate the provenance of vendor updates, and monitor for unexpected changes to the integrity of signed binaries in the software supply chain.',
    ],
    cite: 'guidance · mitigation',
  },
];

const sources = [
  'Vendor discovery report — supply-chain compromise analysis (2017)',
  'Independent malware analysis — module and C2 behavior',
  'Government advisory — associated intrusion-set activity',
  'Public sandbox detonation — observed host behavior',
];

export default function SampleReport() {
  return (
    <main data-surface="sample-report" className="overflow-x-hidden bg-[var(--surface-0)]">
      <div className="border-b border-zinc-200 bg-white">
        <div className="mx-auto flex max-w-4xl flex-col items-start justify-between gap-3 px-6 py-4 sm:flex-row sm:items-center lg:px-8">
          <p className="text-base text-zinc-600">
            <span className="font-medium text-zinc-950">Sample report.</span> A real
            example of SentrySearch output — no account needed.
          </p>
          <Link
            href="/auth/signup"
            className="group inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-lg bg-zinc-950 px-4 text-base font-medium text-white transition-colors duration-150 hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2"
          >
            Generate your own
            <ArrowRightIcon className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5" />
          </Link>
        </div>
      </div>

      <article className="mx-auto max-w-4xl px-6 py-12 lg:px-8">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-base text-zinc-500 transition-colors hover:text-zinc-800"
        >
          <ArrowLeftIcon className="h-4 w-4" />
          Back to home
        </Link>

        <header className="fade-up mt-8">
          <p className="text-sm font-medium text-blue-700">Threat intelligence report</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <h1 className="font-mono text-3xl font-semibold tracking-tight text-zinc-950">ShadowPad</h1>
            <span className="rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">
              High confidence
            </span>
          </div>
          <p className="mt-4 max-w-2xl text-lg leading-8 text-zinc-600">
            A source-backed profile of the ShadowPad backdoor: how it operates, how
            to detect it, and how to reduce exposure — with the evidence behind each
            section.
          </p>
        </header>

        <dl className="fade-up fade-up-1 mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-zinc-200 bg-zinc-200 sm:grid-cols-4">
          {signals.map((s) => (
            <div key={s.label} className="bg-white px-5 py-4">
              <dt className="text-sm text-zinc-500">{s.label}</dt>
              <dd className="mt-1 text-lg font-semibold text-zinc-950">{s.value}</dd>
              <dd className="mt-0.5 text-sm text-zinc-500">{s.detail}</dd>
            </div>
          ))}
        </dl>

        <div className="fade-up fade-up-2 mt-12 space-y-10">
          {sections.map((section) => (
            <section key={section.heading}>
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-950">{section.heading}</h2>
              <div className="mt-3 space-y-3">
                {section.paras.map((p, i) => (
                  <p key={i} className="text-base leading-7 text-zinc-700">{p}</p>
                ))}
              </div>
              <p className="mt-3 font-mono text-sm text-zinc-500">{section.cite}</p>
            </section>
          ))}
        </div>

        <section className="mt-12 rounded-xl border border-zinc-200 bg-white p-6">
          <h2 className="text-base font-semibold text-zinc-950">Sources</h2>
          <ol className="mt-4 space-y-3">
            {sources.map((src, i) => (
              <li key={i} className="flex gap-3 text-base leading-7 text-zinc-700">
                <span className="font-mono text-sm text-zinc-400">{String(i + 1).padStart(2, '0')}</span>
                <span>{src}</span>
              </li>
            ))}
          </ol>
        </section>

        <div className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-950 px-6 py-12 text-center sm:px-12">
          <h2 className="text-2xl font-semibold tracking-tight text-white">
            Run this on a target of your own
          </h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-zinc-300">
            Create a workspace to generate source-backed reports and keep your saved
            intelligence in one place.
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
      </article>
    </main>
  );
}
