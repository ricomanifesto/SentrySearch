'use client';

import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  DocumentTextIcon,
  SparklesIcon,
  ClockIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Badge } from '@/components/ui/Badge';

interface GenerateFormData {
  tool_name: string;
  enable_ml_guidance: boolean;
  analysis_type: 'comprehensive' | 'quick' | 'custom';
}

const analysisTypeOptions = [
  { value: 'comprehensive', label: 'Comprehensive Analysis' },
  { value: 'quick', label: 'Quick Analysis' },
  { value: 'custom', label: 'Custom Analysis' },
];

const targetGroups = [
  {
    label: 'Observed threats',
    examples: ['ShadowPad', 'Cobalt Strike', 'BumbleBee', 'StealC'],
  },
  {
    label: 'Exposed technologies',
    examples: ['SAP NetWeaver', 'Microsoft Exchange', 'VMware vCenter', 'AnyDesk'],
  },
];

const analysisSummaries = [
  {
    name: 'Comprehensive',
    detail: 'Technical profile, detection guidance, mitigations, and source-backed context.',
    time: '2-5 min',
    variant: 'info' as const,
  },
  {
    name: 'Quick',
    detail: 'Fast triage summary with high-signal indicators and immediate next steps.',
    time: '30-60s',
    variant: 'success' as const,
  },
  {
    name: 'Custom',
    detail: 'Focused analysis for a specific campaign, asset class, or review workflow.',
    time: 'Variable',
    variant: 'warning' as const,
  },
];

const qualityChecks = [
  'Source-backed findings',
  'Detection and mitigation guidance',
  'Risk and confidence framing',
  'Review-ready report record',
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

  return (
    <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="mb-8 max-w-3xl">
          <Badge variant="info" size="sm" className="mb-3 rounded-md">
            Report workspace
          </Badge>
          <h1 className="max-w-full text-2xl font-semibold leading-tight tracking-normal text-slate-950 sm:text-4xl">
            Generate a threat intelligence report
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
            Start with a malware family, attack tool, vulnerability target, or exposed technology.
            SentrySearch will assemble a review-ready profile with detection and mitigation context.
          </p>
        </div>

        <div className="grid min-w-0 grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <Card className="min-w-0 border-slate-200 shadow-sm">
            <CardHeader className="border-b border-slate-100 pb-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <CardTitle className="flex items-center gap-2 text-xl">
                    <DocumentTextIcon className="h-5 w-5 text-blue-600" />
                    Intelligence request
                  </CardTitle>
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                    Define the target and depth before generation. The report is saved after the request completes.
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
                  placeholder="ShadowPad, Cobalt Strike, SAP NetWeaver"
                  value={formData.tool_name}
                  onChange={(e) => setFormData(prev => ({ ...prev, tool_name: e.target.value }))}
                  helpText="Use the exact name analysts or asset owners use in tickets and reports."
                  disabled={isLoading}
                  required
                  className="h-12 text-base"
                />

                <div className="grid min-w-0 grid-cols-1 gap-5 md:grid-cols-[minmax(0,1fr)_minmax(16rem,0.8fr)]">
                  <Select
                    label="Analysis depth"
                    options={analysisTypeOptions}
                    value={formData.analysis_type}
                    onChange={(e) => setFormData(prev => ({ ...prev, analysis_type: e.target.value as 'comprehensive' | 'quick' | 'custom' }))}
                    helpText="Choose the review depth before generation."
                    disabled={isLoading}
                    className="h-12"
                  />

                  <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        id="ml_guidance"
                        checked={formData.enable_ml_guidance}
                        onChange={(e) => setFormData(prev => ({ ...prev, enable_ml_guidance: e.target.checked }))}
                        disabled={isLoading}
                        className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                      />
                      <div>
                        <label htmlFor="ml_guidance" className="flex items-center gap-1 text-sm font-medium text-slate-900">
                          <SparklesIcon className="h-4 w-4 text-blue-600" />
                          ML-powered guidance
                        </label>
                        <p className="mt-1 text-sm leading-5 text-slate-600">
                          Add behavioral cues, detection ideas, and risk framing to the generated profile.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

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

                <div className="flex flex-col gap-3 border-t border-slate-100 pt-6 sm:flex-row sm:items-center sm:justify-between">
                  <p className="text-sm leading-6 text-slate-600">
                    Reports are saved automatically when generation succeeds.
                  </p>
                  <Button
                    type="submit"
                    size="lg"
                    loading={isLoading}
                    disabled={!formData.tool_name.trim() || isLoading}
                    className="min-h-12 w-full whitespace-normal px-5 text-sm sm:w-auto"
                  >
                    {isLoading ? 'Generating report...' : 'Generate report'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          <aside className="min-w-0 space-y-4">
            <Card className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="text-base">Seed a target</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {targetGroups.map((group) => (
                    <div key={group.label}>
                      <h4 className="text-sm font-medium text-slate-800">{group.label}</h4>
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

            <Card className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="text-base">Analysis modes</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {analysisSummaries.map((summary) => (
                    <div key={summary.name} className="border-b border-slate-100 pb-4 last:border-0 last:pb-0">
                      <div className="flex items-start justify-between gap-3">
                        <span className="text-sm font-medium text-slate-900">{summary.name}</span>
                        <Badge variant={summary.variant} size="sm" className="shrink-0 rounded-md">
                          {summary.time}
                        </Badge>
                      </div>
                      <p className="mt-1 text-sm leading-6 text-slate-600">{summary.detail}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <SparklesIcon className="h-4 w-4 text-blue-600" />
                  Report quality checks
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm leading-6 text-slate-600">
                  {qualityChecks.map((check) => (
                    <li key={check} className="flex gap-2">
                      <span className="mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-blue-600" />
                      <span>{check}</span>
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
