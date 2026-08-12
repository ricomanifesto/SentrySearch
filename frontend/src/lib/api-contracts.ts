/** Stable wire contracts shared by the SentrySearch frontend. */

export type ReportStatus = 'generating' | 'completed' | 'failed';
export type ReportSortField = 'created_at' | 'quality_score' | 'tool_name' | 'processing_time_ms';
export type SortOrder = 'asc' | 'desc';

export interface Report {
  id: string;
  tool_name: string;
  category: string;
  threat_type: string;
  quality_score: number;
  created_at: string;
  processing_time_ms: number;
  status?: ReportStatus;
  content_preview?: string;
}

export interface ReportDetail extends Report {
  markdown_content?: string;
  threat_data?: Record<string, unknown>;
  search_tags: string[];
}

export interface ReportCreateRequest {
  tool_name: string;
  enable_ml_guidance?: boolean;
  analysis_type?: 'comprehensive' | 'quick' | 'custom';
}

export interface ListReportFilters {
  query?: string;
  threat_type?: string;
  min_quality?: number;
  sort_by?: ReportSortField;
  sort_order?: SortOrder;
}

export interface SearchFilters {
  query?: string;
  threat_types?: string[];
  date_range_days?: number;
  min_quality_score?: number;
  tags?: string[];
}

export interface ReportSort {
  sort_by?: ReportSortField;
  sort_order?: SortOrder;
}

export interface PaginatedResponse<T> {
  reports: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface AnalyticsDashboard {
  summary: {
    total_reports: number;
    reports_this_week: number;
    avg_quality_score: number;
  };
  threat_distribution: Record<string, number>;
  quality_distribution: Record<string, number>;
  recent_activity: Array<{
    id: string;
    tool_name: string;
    created_at: string;
    quality_score: number;
  }>;
}

export interface AnalyticsData {
  overview: {
    total_reports: number;
    reports_last_24h: number;
    reports_last_7d: number;
    reports_last_30d: number;
    avg_quality_score: number;
    avg_processing_time_ms: number;
    most_common_threat_type: string;
    success_rate: number;
  };
  trends: {
    daily_reports: Array<{ date: string; count: number }>;
    threat_type_distribution: Array<{ threat_type: string; count: number; percentage: number }>;
    quality_score_distribution: Array<{ range: string; count: number; percentage: number }>;
    processing_time_trends: Array<{ date: string; avg_time_ms: number }>;
  };
  recent_activity: Array<{
    id: string;
    tool_name: string;
    quality_score: number;
    processing_time_ms: number;
    created_at: string;
    threat_type?: string;
  }>;
}

export interface SearchFilterOptions {
  threat_types: string[];
  categories: string[];
  tags: string[];
  quality_range: { min: number; max: number };
  date_range_options: Array<{ label: string; days: number }>;
}

export type ExportFormat = 'json' | 'csv' | 'markdown' | 'xml';

export interface ExportConfig extends Record<string, unknown> {
  format: ExportFormat;
  include_content: boolean;
  include_metadata: boolean;
  include_tags: boolean;
  date_range_days?: number;
  threat_types?: string[];
  min_quality_score?: number;
  max_reports?: number;
  selected_reports?: string[];
}

export interface ActivityEvent {
  id: string;
  type: 'report_created';
  description: string;
  metadata: Record<string, unknown>;
  created_at: string;
  severity: 'success';
}
