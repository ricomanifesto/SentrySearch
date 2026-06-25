/**
 * Individual Report Detail Page
 * 
 * Displays a single threat intelligence report with full content,
 * metadata, and export options.
 */

'use client';

import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams, useRouter } from 'next/navigation';
import {
  DocumentTextIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  ClockIcon,
  StarIcon,
  TagIcon,
  ArrowLeftIcon,
  CircleStackIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, downloadAsFile } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge, type BadgeProps } from '@/components/ui/Badge';
import { AuthGuard } from '@/components/AuthGuard';

export default function ReportDetailPage() {
  return (
    <AuthGuard>
      <ReportDetailContent />
    </AuthGuard>
  );
}

function ReportDetailContent() {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const reportId = params?.id as string;

  // Fetch report data
  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', reportId],
    queryFn: () => api.getReport(reportId, true),
    enabled: !!reportId,
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => api.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      router.push('/reports');
    },
  });

  const handleDownload = () => {
    if (!report?.markdown_content) return;
    
    const filename = `${report.tool_name.replace(/[^a-zA-Z0-9]/g, '_')}_report.md`;
    downloadAsFile(report.markdown_content, filename, 'text/markdown');
  };

  const handleDelete = () => {
    if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen overflow-x-hidden bg-[#f7f7f3] py-6 sm:py-10">
        <div
          className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8"
          role="status"
          aria-label="Loading report record"
        >
          <div className="animate-pulse space-y-5">
            <div className="h-4 w-40 bg-[#d9dbcf]" />
            <div className="h-10 w-2/3 bg-[#d9dbcf]" />
            <div className="grid gap-4 md:grid-cols-3">
              <div className="h-28 bg-white" />
              <div className="h-28 bg-white" />
              <div className="h-28 bg-white" />
            </div>
            <div className="h-80 bg-white" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen overflow-x-hidden bg-[#f7f7f3] px-4 py-10 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl border border-[#efc7c3] bg-[#fff7f6] px-6 py-10 text-center sm:px-10" role="alert">
          <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-[#a43c34]" />
          <h1 className="text-2xl font-semibold text-[#4c201d]">Report record unavailable</h1>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-[#7b332d]">
            This saved intelligence record could not be opened. Return to the review queue and try another report.
          </p>
          <Button variant="outline" onClick={() => router.push('/reports')} className="mt-6">
            Back to saved intelligence
          </Button>
        </div>
      </div>
    );
  }

  const qualityScore = report.quality_score || 0;
  const qualityVariant: BadgeProps['variant'] =
    qualityScore >= 4.0 ? 'success' :
    qualityScore >= 3.0 ? 'info' :
    qualityScore >= 2.0 ? 'warning' : 'error';
  const qualityLabel =
    qualityScore >= 4.0 ? 'High confidence' :
    qualityScore >= 3.0 ? 'Reviewable' :
    qualityScore >= 2.0 ? 'Needs review' : 'Low confidence';
  const metadataCards = [
    {
      label: 'Confidence',
      value: `${qualityScore.toFixed(1)} / 5.0`,
      detail: qualityLabel,
      icon: StarIcon,
      badgeVariant: qualityVariant,
    },
    {
      label: 'Category',
      value: report.category || 'Unclassified',
      detail: 'Report classification',
      icon: TagIcon,
      badgeVariant: 'info' as const,
    },
    {
      label: 'Threat type',
      value: report.threat_type || 'Unclassified',
      detail: 'Observed behavior family',
      icon: ShieldCheckIcon,
      badgeVariant: 'success' as const,
    },
  ];

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#f7f7f3] py-6 text-[#171915] sm:py-10">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="mb-6">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.back()}
            className="mb-5 gap-2 text-[#4f564d]"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to review queue
          </Button>

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
            <div className="min-w-0">
              <Badge variant={qualityVariant} size="sm" className="mb-3 rounded-md">
                {qualityLabel} intelligence record
              </Badge>
              <h1 className="text-3xl font-semibold leading-tight text-[#171915] sm:text-5xl">
                {report.tool_name}
              </h1>
              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-sm text-[#5d6458]">
                <span className="inline-flex items-center gap-1">
                  <ClockIcon className="h-4 w-4" />
                  {formatRelativeTime(report.created_at)}
                </span>
                <span>{formatDate(report.created_at)}</span>
                {report.processing_time_ms ? (
                  <span>{formatProcessingTime(report.processing_time_ms)} generation</span>
                ) : null}
              </div>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row lg:justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={handleDownload}
                disabled={!report.markdown_content}
                className="min-h-10 gap-2"
              >
                <ArrowDownTrayIcon className="h-4 w-4" />
                Download markdown
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDelete}
                loading={deleteMutation.isPending}
                className="min-h-10 gap-2"
              >
                <TrashIcon className="h-4 w-4" />
                Delete record
              </Button>
            </div>
          </div>
        </div>

        <div className="mb-8 grid gap-4 md:grid-cols-3">
          {metadataCards.map((item) => {
            const Icon = item.icon;

            return (
              <div key={item.label} className="border border-[#d8d9ce] bg-white px-5 py-4">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold uppercase tracking-[0.14em] text-[#6f755f]">
                    {item.label}
                  </span>
                  <Icon className="h-5 w-5 text-[#6f755f]" />
                </div>
                <div className="text-2xl font-semibold text-[#171915]">{item.value}</div>
                <Badge variant={item.badgeVariant} size="sm" className="mt-3 rounded-md">
                  {item.detail}
                </Badge>
              </div>
            );
          })}
        </div>

        {report.search_tags && report.search_tags.length > 0 && (
          <section className="mb-8 border border-[#d8d9ce] bg-white p-5">
            <div className="mb-4 flex items-center gap-2">
              <TagIcon className="h-5 w-5 text-[#6f755f]" />
              <h2 className="text-base font-semibold text-[#20231f]">Search and review tags</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {report.search_tags.map((tag, index) => (
                <Badge key={index} variant="default" size="sm" className="rounded-md">
                  {tag}
                </Badge>
              ))}
            </div>
          </section>
        )}

        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_18rem]">
          <Card className="border-[#d8d9ce] shadow-sm">
            <CardHeader>
              <CardTitle>Intelligence narrative</CardTitle>
            </CardHeader>
            <CardContent>
              {report.markdown_content ? (
                <article className="max-w-none">
                  <pre className="whitespace-pre-wrap break-words border-l border-[#b9bea8] bg-[#fbfbf7] px-5 py-4 text-sm leading-7 text-[#2f332d]">
                    {report.markdown_content}
                  </pre>
                </article>
              ) : (
                <div className="border border-[#e4e5da] bg-[#fbfbf7] px-5 py-8 text-center text-[#5d6458]">
                  <DocumentTextIcon className="mx-auto mb-4 h-12 w-12 text-[#8b927f]" />
                  <h2 className="text-base font-semibold text-[#20231f]">Narrative unavailable</h2>
                  <p className="mx-auto mt-2 max-w-md text-sm leading-6">
                    This report record does not include saved markdown content. Use the structured extraction data and tags for review context.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          <aside className="space-y-4">
            <div className="border border-[#d8d9ce] bg-white p-5">
              <div className="mb-3 flex items-center gap-2">
                <ShieldCheckIcon className="h-5 w-5 text-[#6f755f]" />
                <h2 className="text-base font-semibold text-[#20231f]">Review posture</h2>
              </div>
              <p className="text-sm leading-6 text-[#5d6458]">
                Compare the narrative against its category, threat type, and saved extraction data before using the report in follow-up analysis.
              </p>
            </div>

            <div className="border border-[#d8d9ce] bg-white p-5">
              <div className="mb-3 flex items-center gap-2">
                <CircleStackIcon className="h-5 w-5 text-[#6f755f]" />
                <h2 className="text-base font-semibold text-[#20231f]">Source context</h2>
              </div>
              <p className="text-sm leading-6 text-[#5d6458]">
                Source transparency is preserved through the saved report narrative, search tags, and structured technical extraction below.
              </p>
            </div>
          </aside>
        </div>

        {report.threat_data && (
          <Card className="mt-8 border-[#d8d9ce] shadow-sm">
            <CardHeader>
              <CardTitle>Structured extraction data</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="max-h-[32rem] overflow-auto border border-[#e4e5da] bg-[#fbfbf7] p-4 text-xs leading-6 text-[#2f332d]">
                {JSON.stringify(report.threat_data, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
