'use client';

import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  DocumentMagnifyingGlassIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { AuthGuard } from '@/components/AuthGuard';

interface GenerateFormData {
  tool_name: string;
  enable_ml_guidance: boolean;
  analysis_type: 'comprehensive' | 'quick' | 'custom';
}

type TargetSeedGroup = {
  label: string;
  description: string;
  examples: string[];
};

const targetGroups: TargetSeedGroup[] = [
  {
    label: 'Observed threats',
    description: 'Malware families and attack tools already seen in analyst queues.',
    examples: ['ShadowPad', 'Cobalt Strike', 'BumbleBee', 'StealC'],
  },
  {
    label: 'Exposed technologies',
    description: 'Vulnerable or exposed platforms that need source-backed review.',
    examples: ['SAP NetWeaver', 'Microsoft Exchange', 'VMware vCenter', 'AnyDesk'],
  },
];

const reportIncludes = [
  {
    label: 'Source-backed findings',
    description: 'Claims tied back to the source context and extracted evidence.',
  },
  {
    label: 'Detection and mitigation',
    description: 'Defender-oriented guidance when the source material supports it.',
  },
  {
    label: 'Risk and confidence framing',
    description: 'Confidence and risk posture, surfaced before you save or share.',
  },
  {
    label: 'A saved review record',
    description: 'Output lands as a saved report, ready for follow-up review.',
  },
];

export default function GeneratePage() {
  const router = useRouter();
  const [formData, setFormData] = useState<GenerateFormData>({
    tool_name: '',
    enable_ml_guidance: true,
    analysis_type: 'comprehensive',
  });

  const generateMutation = useMutation({
    mutationFn: (data: GenerateFormData) => api.createReport(data),
    onSuccess: (result) => {
      router.push(`/reports/${result.report_id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.tool_name.trim()) return;
    generateMutation.mutate(formData);
  };

  const isLoading = generateMutation.isPending;
  const error = generateMutation.error;
  const targetName = formData.tool_name.trim();
  const fieldClass =
    'mt-2 block h-12 w-full rounded-lg border border-zinc-300 bg-white px-3 text-base text-zinc-950 outline-none transition-colors placeholder:text-zinc-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 disabled:cursor-not-allowed disabled:opacity-60';

  return (
    <AuthGuard>
      <main data-surface="generate-console" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <header className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">Generate</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">
              Generate a threat intelligence report
            </h1>
            <p className="mt-4 text-lg leading-8 text-zinc-600">
              Name a malware family, attack tool, or exposed technology. SentrySearch
              researches it and assembles a source-backed report with detection and
              mitigation guidance.
            </p>
          </header>

          <div className="mt-10 grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,1fr)_20rem]">
            <form onSubmit={handleSubmit} className="rounded-xl border border-zinc-200 bg-white p-6">
              <label htmlFor="tool_name" className="block text-sm font-medium text-zinc-800">
                Target
              </label>
              <input
                id="tool_name"
                type="text"
                placeholder="ShadowPad or SAP NetWeaver"
                value={formData.tool_name}
                onChange={(e) => setFormData((prev) => ({ ...prev, tool_name: e.target.value }))}
                disabled={isLoading}
                required
                className={fieldClass}
              />
              <p className="mt-2 text-sm text-zinc-500">
                Use the exact name analysts or asset owners use in tickets and reports.
              </p>

              <label className="mt-6 flex cursor-pointer items-start gap-3 rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4 transition-colors hover:border-zinc-300">
                <input
                  type="checkbox"
                  checked={formData.enable_ml_guidance}
                  onChange={(e) => setFormData((prev) => ({ ...prev, enable_ml_guidance: e.target.checked }))}
                  disabled={isLoading}
                  className="mt-0.5 h-4 w-4 rounded border-zinc-300 text-blue-600 focus:ring-blue-500"
                />
                <span>
                  <span className="block text-sm font-medium text-zinc-950">
                    Include detection and mitigation guidance
                  </span>
                  <span className="mt-1 block text-sm leading-6 text-zinc-600">
                    Adds detection ideas, behavioral cues, and risk framing to the
                    report. Turn off to stay closer to raw source extraction.
                  </span>
                </span>
              </label>

              {error && (
                <div role="alert" className="mt-6 rounded-lg border border-red-200 bg-red-50 p-4">
                  <div className="flex gap-3">
                    <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-red-600" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium text-red-900">Couldn&apos;t generate the report</p>
                      <p className="mt-1 text-sm leading-6 text-red-700">
                        Check the target name and try again.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {isLoading && (
                <div role="status" className="mt-6 rounded-lg border border-blue-200 bg-blue-50 p-4">
                  <div className="flex gap-3">
                    <span className="mt-1 h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-blue-300 border-t-blue-700" aria-hidden="true" />
                    <div>
                      <p className="text-sm font-medium text-blue-900">Generating the report</p>
                      <p className="mt-1 text-sm leading-6 text-blue-800">
                        Research and synthesis can take a few minutes. Keep this page
                        open — you&apos;ll be taken to the report when it&apos;s ready.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={!targetName || isLoading}
                className="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-zinc-950 px-5 text-base font-medium text-white transition-colors hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
              >
                <DocumentMagnifyingGlassIcon className="h-5 w-5" aria-hidden="true" />
                {isLoading ? 'Generating…' : 'Generate report'}
              </button>
            </form>

            <aside className="space-y-6">
              <section data-contract="Generate.TargetSeedLibrary.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">Try a target</h2>
                <div className="mt-4 space-y-4">
                  {targetGroups.map((group) => (
                    <div key={group.label}>
                      <h3 className="text-sm font-medium text-zinc-800">{group.label}</h3>
                      <p className="mt-1 text-sm leading-6 text-zinc-500">{group.description}</p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {group.examples.map((example) => (
                          <button
                            key={example}
                            type="button"
                            onClick={() => setFormData((prev) => ({ ...prev, tool_name: example }))}
                            disabled={isLoading}
                            className="rounded-md border border-zinc-200 bg-white px-2.5 py-1.5 text-sm font-medium text-zinc-700 transition-colors hover:border-zinc-300 hover:bg-zinc-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {example}
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section data-contract="Generate.ReportIncludes.v1" className="rounded-xl border border-zinc-200 bg-white p-5">
                <h2 className="text-base font-semibold text-zinc-950">What each report includes</h2>
                <ul className="mt-4 space-y-3">
                  {reportIncludes.map((item) => (
                    <li key={item.label}>
                      <p className="text-sm font-medium text-zinc-950">{item.label}</p>
                      <p className="mt-0.5 text-sm leading-6 text-zinc-500">{item.description}</p>
                    </li>
                  ))}
                </ul>
              </section>
            </aside>
          </div>
        </div>
      </main>
    </AuthGuard>
  );
}
