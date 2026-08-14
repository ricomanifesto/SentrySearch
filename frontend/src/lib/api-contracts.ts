/** Stable wire contracts shared by the SentrySearch frontend. */

export type ReportStatus = 'generating' | 'completed' | 'failed';
export type EvaluationStatus = 'unrecorded' | 'pending' | 'completed' | 'failed';
export type ReviewStatus = 'generating' | 'generation_failed' | 'evaluation_pending' | 'needs_evaluation' | 'needs_attention' | 'reviewable';
export type GenerationStage = 'queued' | 'researching' | 'synthesizing' | 'validating' | 'finalizing' | 'completed' | 'failed';
export type ReportSortField = 'created_at' | 'quality_score' | 'tool_name' | 'processing_time_ms';
export type SortOrder = 'asc' | 'desc';

export interface Report {
  id: string;
  tool_name: string;
  category: string;
  threat_type: string;
  quality_score: number | null;
  created_at: string;
  processing_time_ms: number;
  status?: ReportStatus;
  generation_stage?: GenerationStage;
  evaluation_status: EvaluationStatus;
  evaluation_error_code?: string | null;
  evaluation_attempts: number;
  evaluated_at?: string | null;
  review_status: ReviewStatus;
  content_preview?: string | null;
}

export interface ReportDetail extends Report {
  markdown_content?: string;
  threat_data?: Record<string, unknown>;
  web_sources: ReportSource[];
  search_tags: string[];
  generation_route?: ModelRouteProvenance | null;
  evaluation_route?: ModelRouteProvenance | null;
  quality_assessment?: Record<string, unknown> | null;
}

export interface ModelRouteProvenance {
  requested_models: string[];
  requested_providers: string[];
  selected_models: string[];
  actual_models: string[];
  providers: string[];
  used_fallback: boolean;
  request_count: number;
}

export interface ReportSource {
  title: string;
  url: string;
  domain: string;
  access_date: string;
  relevance_score: string;
  content_type: string;
  key_findings: string;
}

export interface ReportCreateRequest {
  tool_name: string;
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
    avg_quality_score: number | null;
    scored_reports: number;
    needs_attention_reports: number;
  };
  threat_distribution: Record<string, number>;
  quality_distribution: Array<{ range: string; count: number }>;
  recent_activity: Array<{
    id: string;
    tool_name: string;
    created_at: string;
    quality_score: number | null;
    evaluation_status: EvaluationStatus;
    review_status: ReviewStatus;
  }>;
}

export interface AnalyticsData {
  overview: {
    total_reports: number;
    reports_last_24h: number;
    reports_last_7d: number;
    reports_in_period: number;
    avg_quality_score: number | null;
    avg_processing_time_ms: number | null;
    most_common_threat_type: string;
    generation_completion_rate: number | null;
    terminal_reports: number;
    scored_reports: number;
    unscored_reports: number;
    evaluation_failed_reports: number;
    reviewable_reports: number;
    needs_attention_reports: number;
  };
  trends: {
    daily_reports: Array<{ date: string; count: number }>;
    threat_type_distribution: Array<{ threat_type: string; count: number; percentage: number }>;
    quality_score_distribution: Array<{ range: string; count: number; percentage: number }>;
    processing_time_trends: Array<{ date: string; avg_time_ms: number }>;
  };
  route_performance: Array<{
    route: 'primary' | 'fallback' | 'unrecorded';
    report_count: number;
    scored_report_count: number;
    runtime_recorded_count: number;
    avg_quality_score: number | null;
    avg_processing_time_ms: number | null;
  }>;
  recent_activity: Array<{
    id: string;
    tool_name: string;
    quality_score: number | null;
    processing_time_ms: number | null;
    created_at: string;
    threat_type?: string;
    generation_used_fallback: boolean | null;
    evaluation_status: EvaluationStatus;
    review_status: ReviewStatus;
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
  include_sources: boolean;
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
  severity: 'success' | 'warning' | 'info';
}
