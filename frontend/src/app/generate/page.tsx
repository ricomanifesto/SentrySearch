'use client';

import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  DocumentTextIcon,
  SparklesIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { SurfaceHeader } from '@/components/ui/SurfaceHeader';

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

type QualityGateRow = {
  label: string;
  status: string;
  description: string;
};

const targetGroups: TargetSeedGroup[] = [
  {
    label: 'Observed threats',
    description: 'Seed requests with malware families and attack tools already seen in analyst queues.',
    examples: ['ShadowPad', 'Cobalt Strike', 'BumbleBee', 'StealC'],
  },
  {
    label: 'Exposed technologies',
    description: 'Start from vulnerable or exposed platforms that need source-backed review.',
    examples: ['SAP NetWeaver', 'Microsoft Exchange', 'VMware vCenter', 'AnyDesk'],
  },
];

const reviewDepthOptions = [
  {
    value: 'comprehensive',
    name: 'Full intelligence brief',
    detail: 'Technical profile, detection guidance, mitigations, and source-backed context.',
    sla: '2-5 min',
    variant: 'info' as const,
    evidence: ['source-backed narrative', 'detection guidance', 'mitigation context'],
  },
  {
    value: 'quick',
    name: 'Triage brief',
    detail: 'Fast triage summary with high-signal indicators and immediate next steps.',
    sla: '30-60s',
    variant: 'success' as const,
    evidence: ['priority signals', 'immediate actions', 'review queue handoff'],
  },
  {
    value: 'custom',
    name: 'Focused analyst note',
    detail: 'Focused analysis for a specific campaign, asset class, or review queue.',
    sla: 'Variable',
    variant: 'warning' as const,
    evidence: ['campaign framing', 'asset context', 'analyst-specific scope'],
  },
];

const qualityGates: QualityGateRow[] = [
  {
    label: 'Source-backed findings',
    status: 'Required',
    description: 'The report should tie claims back to collected source context and extracted evidence.',
  },
  {
    label: 'Detection and mitigation guidance',
    status: 'Expected',
    description: 'Output should include useful defender actions when the source material supports them.',
  },
  {
    label: 'Risk and confidence framing',
    status: 'Expected',
    description: 'Analysts should see confidence and risk posture before saving or sharing the record.',
  },
  {
    label: 'Review-ready report record',
    status: 'Required',
    description: 'Generated output should land as a saved intelligence record ready for follow-up review.',
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
      // Redirect to the generated report
      router.push(`/reports/${result.report_id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.tool_name.trim()) return;

    generateMutation.mutate(formData);
  };

  const handleExampleClick = (example: string) => {
    setFormData(prev => ({ ...prev, tool_name: example }));
  };

  const isLoading = generateMutation.isPending;
  const error = generateMutation.error;
  const selectedMode = reviewDepthOptions.find((option) => option.value === formData.analysis_type);
  const targetName = formData.tool_name.trim();
  const submissionHandoffChecks = [
    {
      label: 'Target',
      status: targetName ? 'Ready' : 'Needed',
      description: targetName
        ? `${targetName} is queued as the report target.`
        : 'Name the threat, tool, vulnerability, or exposed technology to investigate.',
      tone: targetName ? 'ready' : 'needed',
    },
    {
      label: 'Review depth',
      status: selectedMode?.name ?? 'Needed',
      description: selectedMode
        ? `${selectedMode.sla} handoff with ${selectedMode.evidence[0]}.`
        : 'Choose the analyst handoff SentrySearch should prepare.',
      tone: selectedMode ? 'ready' : 'needed',
    },
    {
      label: 'Guidance layer',
      status: formData.enable_ml_guidance ? 'Enabled' : 'Disabled',
      description: formData.enable_ml_guidance
        ? 'Behavioral cues, detection ideas, and risk framing will be included.'
        : 'The report will stay closer to source extraction without extra guidance.',
      tone: formData.enable_ml_guidance ? 'ready' : 'muted',
    },
  ];

  return (
    <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <SurfaceHeader
          eyebrow="Analyst intake console"
          title="Scope the next threat intelligence request"
          description="Start with a malware family, attack tool, vulnerability target, or exposed technology. SentrySearch will assemble a review-ready profile with detection and mitigation context."
        />

        <div className="grid min-w-0 grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <Card className="min-w-0 border-slate-200 shadow-sm">
            <CardHeader className="border-b border-slate-100 pb-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <CardTitle className="flex items-center gap-2 text-xl">
                    <DocumentTextIcon className="h-5 w-5 text-blue-600" />
                    Request dossier
                  </CardTitle>
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                    Name the target, choose the review depth, and confirm the handoff before generation.
                  </p>
                </div>
                <Badge variant={formData.enable_ml_guidance ? 'success' : 'default'} size="sm" className="w-fit rounded-md">
                  {formData.enable_ml_guidance ? 'ML guidance on' : 'ML guidance off'}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="pt-1">
              <form onSubmit={handleSubmit} className="space-y-6">
                <Input
                  label="Target"
                  placeholder="ShadowPad or SAP NetWeaver"
                  value={formData.tool_name}
                  onChange={(e) => setFormData(prev => ({ ...prev, tool_name: e.target.value }))}
                  helpText="Use the exact name analysts or asset owners use in tickets and reports."
                  disabled={isLoading}
                  required
                  className="h-12 text-base"
                />

                <fieldset>
                  <legend className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                    Analysis mode
                  </legend>
                  <p id="analysis-mode-help" className="mt-1 text-sm leading-6 text-slate-600">
                    Pick the analyst handoff SentrySearch should prepare.
                  </p>

                  <div className="mt-3 grid min-w-0 grid-cols-1 gap-3 md:grid-cols-3" aria-describedby="analysis-mode-help">
                    {reviewDepthOptions.map((option) => {
                      const isSelected = formData.analysis_type === option.value;
                      return (
                        <label
                          key={option.value}
                          className={`min-h-36 cursor-pointer rounded-md border p-4 text-left transition focus-within:ring-2 focus-within:ring-blue-500 ${
                            isSelected
                              ? 'border-blue-500 bg-blue-50 text-slate-950 shadow-sm'
                              : 'border-slate-200 bg-white text-slate-800 hover:border-blue-200 hover:bg-slate-50'
                          } ${isLoading ? 'cursor-not-allowed opacity-60' : ''}`}
                        >
                          <input
                            type="radio"
                            name="analysis_type"
                            value={option.value}
                            checked={formData.analysis_type === option.value}
                            onChange={() => setFormData(prev => ({ ...prev, analysis_type: option.value as GenerateFormData['analysis_type'] }))}
                            disabled={isLoading}
                            className="sr-only"
                          />
                          <div className="flex items-start justify-between gap-3">
                            <span className="text-sm font-semibold leading-5">{option.name}</span>
                            <Badge variant={option.variant} size="sm" className="shrink-0 rounded-md">
                              {option.sla}
                            </Badge>
                          </div>
                          <p className="mt-3 text-sm leading-6 text-slate-600">{option.detail}</p>
                          <div className="mt-4 flex flex-wrap gap-2">
                            {option.evidence.map((item) => (
                              <span
                                key={item}
                                className={`rounded-md border px-2 py-1 text-xs font-medium ${
                                  isSelected
                                    ? 'border-blue-200 bg-white text-blue-800'
                                    : 'border-slate-200 bg-slate-50 text-slate-600'
                                }`}
                              >
                                {item}
                              </span>
                            ))}
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </fieldset>

                {error && (
                  <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-4">
                    <div className="flex gap-3">
                      <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-500" />
                      <div>
                        <h3 className="text-sm font-semibold text-red-900">
                          Generation failed
                        </h3>
                        <p className="mt-1 text-sm leading-6 text-red-700">
                          The report could not be generated. Check the target and try again.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {isLoading && (
                  <div role="status" className="rounded-md border border-blue-200 bg-blue-50 p-4">
                    <div className="flex gap-3">
                      <ClockIcon className="mt-0.5 h-5 w-5 flex-shrink-0 animate-spin text-blue-600" />
                      <div>
                        <h3 className="text-sm font-semibold text-blue-900">
                          Building the report
                        </h3>
                        <p className="mt-1 text-sm leading-6 text-blue-800">
                          Keep this page open while the analysis collects source context and prepares the saved report.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <section className="rounded-md border border-slate-200 bg-white">
                  <div className="border-b border-slate-100 p-4 sm:p-5">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <h3 className="text-base font-semibold text-slate-950">Submission handoff</h3>
                        <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-600">
                          Confirm the request is ready for the analyst queue before starting report generation.
                        </p>
                      </div>
                      <Badge variant={targetName ? 'success' : 'warning'} size="sm" className="w-fit rounded-md">
                        {targetName ? 'Ready to queue' : 'Target required'}
                      </Badge>
                    </div>
                  </div>

                  <div className="grid min-w-0 gap-0 divide-y divide-slate-100 lg:grid-cols-[minmax(0,1fr)_18rem] lg:divide-x lg:divide-y-0">
                    <div className="p-4 sm:p-5">
                      <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-1">
                        {submissionHandoffChecks.map((check) => {
                          const isReady = check.tone === 'ready';
                          const isNeeded = check.tone === 'needed';

                          return (
                            <div key={check.label} className="flex min-w-0 gap-3 rounded-md border border-slate-200 bg-slate-50 p-3">
                              {isReady ? (
                                <CheckCircleIcon className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
                              ) : (
                                <ExclamationTriangleIcon className={`mt-0.5 h-5 w-5 shrink-0 ${isNeeded ? 'text-amber-500' : 'text-slate-400'}`} />
                              )}
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="text-sm font-semibold text-slate-900">{check.label}</span>
                                  <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium text-slate-600">
                                    {check.status}
                                  </span>
                                </div>
                                <p className="mt-1 text-sm leading-5 text-slate-600">{check.description}</p>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    <div className="flex flex-col justify-between gap-5 bg-slate-50 p-4 sm:p-5">
                      <label className="flex cursor-pointer items-start gap-3 rounded-md border border-slate-200 bg-white p-3 transition hover:border-blue-200 hover:bg-blue-50">
                        <input
                          type="checkbox"
                          id="ml_guidance"
                          checked={formData.enable_ml_guidance}
                          onChange={(e) => setFormData(prev => ({ ...prev, enable_ml_guidance: e.target.checked }))}
                          disabled={isLoading}
                          className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                        />
                        <span>
                          <span className="flex items-center gap-1 text-sm font-semibold text-slate-900">
                            <SparklesIcon className="h-4 w-4 text-blue-600" />
                            Include guidance
                          </span>
                          <span className="mt-1 block text-sm leading-5 text-slate-600">
                            Include detection ideas, behavioral cues, and risk framing in the generated profile.
                          </span>
                        </span>
                      </label>

                      <div className="space-y-3">
                        <p className="text-sm leading-6 text-slate-600">
                          Start generation when the target, review depth, and guidance layer match the intended handoff.
                        </p>
                        <Button
                          type="submit"
                          size="lg"
                          loading={isLoading}
                          disabled={!targetName || isLoading}
                          className="min-h-12 w-full whitespace-normal px-5 text-sm"
                        >
                          {isLoading ? 'Generating report...' : 'Start report handoff'}
                        </Button>
                      </div>
                    </div>
                  </div>
                </section>
              </form>
            </CardContent>
          </Card>

          <aside className="min-w-0 space-y-4">
            <Card data-contract="Generate.TargetSeedLibrary.v1" className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="text-base">Target seed library</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {targetGroups.map((group) => (
                    <div key={group.label}>
                      <h4 className="text-sm font-medium text-slate-800">{group.label}</h4>
                      <p className="mt-1 text-sm leading-5 text-slate-600">{group.description}</p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {group.examples.map((example) => (
                          <button
                            key={example}
                            type="button"
                            onClick={() => handleExampleClick(example)}
                            disabled={isLoading}
                            className="rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {example}
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card data-contract="Generate.QualityGateChecklist.v1" className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <SparklesIcon className="h-4 w-4 text-blue-600" />
                  Review quality gates
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-3 text-sm leading-6 text-slate-600">
                  {qualityGates.map((gate) => (
                    <li key={gate.label} className="rounded-md border border-slate-200 bg-white p-3">
                      <div className="flex min-w-0 items-start justify-between gap-3">
                        <span className="font-medium text-slate-950">{gate.label}</span>
                        <Badge variant="info" size="sm" className="shrink-0 rounded-md">
                          {gate.status}
                        </Badge>
                      </div>
                      <p className="mt-2 leading-5 text-slate-600">{gate.description}</p>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </aside>
        </div>
      </div>
    </div>
  );
}
