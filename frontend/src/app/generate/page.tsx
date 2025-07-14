/**
 * Report Generation Page
 * 
 * Professional interface for generating threat intelligence reports.
 * Replaces the Gradio interface with a modern React form.
 */

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

const exampleQueries = [
  'ShadowPad',
  'Cobalt Strike',
  'BumbleBee',
  'StealC',
  'SAP NetWeaver',
  'Microsoft Exchange',
  'VMware vCenter',
  'AnyDesk',
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
    <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Generate Report</h1>
        <p className="mt-2 text-gray-600">
          Create comprehensive threat intelligence profiles for malware, attack tools, and targeted technologies
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Form */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <DocumentTextIcon className="h-5 w-5" />
                <span>Threat Intelligence Request</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Target Input */}
                <Input
                  label="Target for Analysis"
                  placeholder="Enter malware name, attack tool, or technology (e.g., ShadowPad, SAP NetWeaver)"
                  value={formData.tool_name}
                  onChange={(e) => setFormData(prev => ({ ...prev, tool_name: e.target.value }))}
                  helpText="Specify the threat, tool, or technology you want to analyze"
                  disabled={isLoading}
                  required
                />

                {/* Analysis Type */}
                <Select
                  label="Analysis Type"
                  options={analysisTypeOptions}
                  value={formData.analysis_type}
                  onChange={(e) => setFormData(prev => ({ ...prev, analysis_type: e.target.value }))}
                  helpText="Choose the depth and scope of analysis"
                  disabled={isLoading}
                />

                {/* ML Guidance Toggle */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Analysis Options
                  </label>
                  <div className="flex items-center space-x-3">
                    <input
                      type="checkbox"
                      id="ml_guidance"
                      checked={formData.enable_ml_guidance}
                      onChange={(e) => setFormData(prev => ({ ...prev, enable_ml_guidance: e.target.checked }))}
                      disabled={isLoading}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    />
                    <label htmlFor="ml_guidance" className="text-sm text-gray-700 flex items-center space-x-1">
                      <SparklesIcon className="h-4 w-4" />
                      <span>Enable ML-powered guidance</span>
                    </label>
                  </div>
                  <p className="mt-1 text-sm text-gray-500">
                    Use machine learning to enhance threat analysis and detection guidance
                  </p>
                </div>

                {/* Error Display */}
                {error && (
                  <div className="bg-red-50 border border-red-200 rounded-md p-4">
                    <div className="flex">
                      <ExclamationTriangleIcon className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
                      <div className="ml-3">
                        <h3 className="text-sm font-medium text-red-800">
                          Generation Failed
                        </h3>
                        <p className="text-sm text-red-700 mt-1">
                          {error?.message || 'Failed to generate report. Please try again.'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Submit Button */}
                <Button
                  type="submit"
                  size="lg"
                  loading={isLoading}
                  disabled={!formData.tool_name.trim() || isLoading}
                  className="w-full"
                >
                  {isLoading ? 'Generating Report...' : 'Generate Threat Intelligence Report'}
                </Button>

                {/* Loading State */}
                {isLoading && (
                  <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                    <div className="flex items-center">
                      <ClockIcon className="h-5 w-5 text-blue-400 flex-shrink-0 animate-spin" />
                      <div className="ml-3">
                        <h3 className="text-sm font-medium text-blue-800">
                          Generating Report
                        </h3>
                        <p className="text-sm text-blue-700 mt-1">
                          This may take 30-60 seconds depending on analysis type and ML guidance settings.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </form>
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Example Queries */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Example Queries</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Attack Tools & Malware</h4>
                  <div className="flex flex-wrap gap-2">
                    {exampleQueries.slice(0, 4).map((example) => (
                      <button
                        key={example}
                        onClick={() => handleExampleClick(example)}
                        disabled={isLoading}
                        className="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 rounded text-gray-700 transition-colors"
                      >
                        {example}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Targeted Technologies</h4>
                  <div className="flex flex-wrap gap-2">
                    {exampleQueries.slice(4).map((example) => (
                      <button
                        key={example}
                        onClick={() => handleExampleClick(example)}
                        disabled={isLoading}
                        className="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 rounded text-gray-700 transition-colors"
                      >
                        {example}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Analysis Types Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Analysis Types</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium">Comprehensive</span>
                    <Badge variant="info" size="sm">2-5 min</Badge>
                  </div>
                  <p className="text-gray-600">
                    Full threat analysis with technical details, detection guidance, and mitigation strategies
                  </p>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium">Quick</span>
                    <Badge variant="success" size="sm">30-60s</Badge>
                  </div>
                  <p className="text-gray-600">
                    Essential information and key threat indicators for rapid assessment
                  </p>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium">Custom</span>
                    <Badge variant="warning" size="sm">Variable</Badge>
                  </div>
                  <p className="text-gray-600">
                    Tailored analysis based on specific requirements and focus areas
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* ML Guidance Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center space-x-2">
                <SparklesIcon className="h-4 w-4" />
                <span>ML Guidance</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-600">
                Machine learning enhancement provides:
              </p>
              <ul className="mt-2 text-sm text-gray-600 space-y-1">
                <li>• Advanced threat pattern recognition</li>
                <li>• Behavioral analysis insights</li>
                <li>• Enhanced detection recommendations</li>
                <li>• Risk assessment scoring</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}