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
} from '@heroicons/react/24/outline';

import { api } from '@/lib/api';
import { formatDate, formatRelativeTime, formatProcessingTime, downloadAsFile } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

export default function ReportDetailPage() {
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
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2 mb-8"></div>
          <div className="space-y-4">
            <div className="h-32 bg-gray-200 rounded"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-8">
        <Card className="border-red-200 bg-red-50">
          <CardContent className="text-center py-8">
            <DocumentTextIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-lg font-semibold text-red-800 mb-2">Report Not Found</h2>
            <p className="text-red-600 mb-4">
              The requested report could not be found or may have been deleted.
            </p>
            <Button variant="outline" onClick={() => router.push('/reports')}>
              Back to Reports
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const qualityScore = report.quality_score || 0;
  const qualityVariant = 
    qualityScore >= 4.0 ? 'success' :
    qualityScore >= 3.0 ? 'info' :
    qualityScore >= 2.0 ? 'warning' : 'error';

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center mb-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.back()}
            className="mr-4"
          >
            <ArrowLeftIcon className="h-4 w-4 mr-1" />
            Back
          </Button>
        </div>
        
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              {report.tool_name}
            </h1>
            <div className="flex items-center space-x-4 text-sm text-gray-500">
              <span className="flex items-center">
                <ClockIcon className="h-4 w-4 mr-1" />
                {formatRelativeTime(report.created_at)}
              </span>
              <span>•</span>
              <span>{formatDate(report.created_at)}</span>
              {report.processing_time_ms && (
                <>
                  <span>•</span>
                  <span>{formatProcessingTime(report.processing_time_ms)} generation</span>
                </>
              )}
            </div>
          </div>
          
          <div className="mt-4 sm:mt-0 flex items-center space-x-3">
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownload}
              disabled={!report.markdown_content}
            >
              <ArrowDownTrayIcon className="h-4 w-4 mr-1" />
              Download
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDelete}
              loading={deleteMutation.isPending}
            >
              <TrashIcon className="h-4 w-4 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </div>

      {/* Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card>
          <CardContent className="text-center py-4">
            <div className="flex items-center justify-center mb-2">
              <StarIcon className="h-5 w-5 text-yellow-400 mr-1" />
              <span className="text-sm font-medium text-gray-600">Quality Score</span>
            </div>
            <Badge variant={qualityVariant} size="lg">
              {qualityScore.toFixed(1)}
            </Badge>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="text-center py-4">
            <div className="flex items-center justify-center mb-2">
              <TagIcon className="h-5 w-5 text-blue-400 mr-1" />
              <span className="text-sm font-medium text-gray-600">Category</span>
            </div>
            <Badge variant="info">
              {report.category || 'Unknown'}
            </Badge>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="text-center py-4">
            <div className="flex items-center justify-center mb-2">
              <DocumentTextIcon className="h-5 w-5 text-green-400 mr-1" />
              <span className="text-sm font-medium text-gray-600">Threat Type</span>
            </div>
            <Badge variant="success">
              {report.threat_type || 'Unknown'}
            </Badge>
          </CardContent>
        </Card>
      </div>

      {/* Tags */}
      {report.search_tags && report.search_tags.length > 0 && (
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="text-base">Tags</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {report.search_tags.map((tag, index) => (
                <Badge key={index} variant="default" size="sm">
                  {tag}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Content */}
      <Card>
        <CardHeader>
          <CardTitle>Threat Intelligence Report</CardTitle>
        </CardHeader>
        <CardContent>
          {report.markdown_content ? (
            <div className="prose prose-sm max-w-none">
              <pre className="whitespace-pre-wrap text-sm text-gray-800 leading-relaxed">
                {report.markdown_content}
              </pre>
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <DocumentTextIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p>No content available for this report.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threat Data */}
      {report.threat_data && (
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>Technical Data</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-gray-50 p-4 rounded overflow-x-auto">
              {JSON.stringify(report.threat_data, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}