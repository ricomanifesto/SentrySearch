'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRightIcon, ArrowLeftIcon } from '@heroicons/react/24/outline';

const signals = [
  { label: 'Confidence', value: '3.5 / 5.0', detail: 'Reviewable' },
  { label: 'Category', value: 'Malware', detail: 'Post-exploitation framework' },
  { label: 'Threat family', value: 'Dual-use', detail: 'Red-team tool abused in attacks' },
  { label: 'Sources', value: '3 cited', detail: 'Linked to findings' },
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
      'Cobalt Strike is a commercial penetration-testing and adversary-simulation platform first released in 2012. Red teams use it to emulate real intrusions — and threat actors routinely abuse cracked or leaked copies to deploy malware and establish persistence on compromised systems.',
      'Its “Beacon” payload has appeared in numerous high-profile incidents, including ransomware operations and data breaches, making it one of the most commonly observed post-exploitation tools in real-world attacks.',
    ],
    cite: 'source · official vendor site + MITRE ATT&CK (S0393)',
  },
  {
    heading: 'Capabilities',
    paras: [
      'Operators deploy a configurable Beacon implant supporting remote command execution, file upload and download, and in-memory payload staging that keeps activity off disk. “Malleable” C2 profiles let attackers reshape network traffic to imitate legitimate services.',
      'Commonly tracked as Beacon or Cobalt Strike Beacon, the tool is actively maintained and remains in active use.',
    ],
    cite: 'source · structured extraction',
  },
  {
    heading: 'Detection guidance',
    paras: [
      'Hunt for beaconing — regular, low-variance callbacks to low-reputation infrastructure that do not match an application’s normal behavior — and account for the jitter and sleep intervals operators use to blend in. Correlate process-creation and image-load telemetry to surface injected or memory-resident Beacon activity.',
      'Map observed behavior to the MITRE ATT&CK coverage for Cobalt Strike (S0393), and apply published Beacon and YARA signatures where available.',
    ],
    cite: 'guidance · detection',
  },
  {
    heading: 'Mitigations',
    paras: [
      'Constrain and monitor outbound traffic, especially long-lived HTTP(S) and DNS sessions to untrusted infrastructure; egress filtering and TLS inspection reduce Beacon command-and-control viability.',
      'Enforce application allow-listing and least privilege to limit payload execution and lateral movement, and prioritize EDR coverage that flags in-memory injection and the named-pipe activity associated with Beacon.',
    ],
    cite: 'guidance · mitigation',
  },
];

const sources = [
  'Official vendor documentation — Cobalt Strike (cobaltstrike.com)',
  'MITRE ATT&CK — Software S0393 (Cobalt Strike)',
  'Vendor threat reporting — observed use in ransomware and intrusion activity',
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
            <h1 className="font-mono text-3xl font-semibold tracking-tight text-zinc-950">Cobalt Strike</h1>
            <span className="rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">
              Reviewable
            </span>
          </div>
          <p className="mt-4 max-w-2xl text-lg leading-8 text-zinc-600">
            A source-backed profile of Cobalt Strike: how it operates, how to
            detect it, and how to reduce exposure — with the evidence behind each
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
