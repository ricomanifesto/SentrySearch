/** Stable wire contracts shared by the SentrySearch frontend. */

export type ReportStatus = 'generating' | 'completed' | 'failed';
export type EvaluationStatus = 'unrecorded' | 'pending' | 'completed' | 'failed';
export type ReviewStatus = 'generating' | 'generation_failed' | 'evaluation_pending' | 'needs_evaluation' | 'needs_attention' | 'reviewable';
export type AnalystDisposition = 'unreviewed' | 'accepted' | 'needs_revision' | 'rejected';
export type StoredAnalystDisposition = Exclude<AnalystDisposition, 'unreviewed'>;
export type ClassificationStatus = 'recorded' | 'reconciled' | 'unmapped' | 'unrecorded';
export type ClaimAttributionStatus = 'attributed' | 'unattributed' | 'legacy';
export type GenerationErrorCode = 'provider_rate_limited' | 'provider_unavailable' | 'provider_timeout' | 'model_output_invalid' | 'evidence_unavailable' | 'evidence_unattested' | 'persistence_failed' | 'unknown';
export type GenerationStage = 'queued' | 'researching' | 'synthesizing' | 'validating' | 'finalizing' | 'completed' | 'failed';
export type GenerationRouteScope = 'synthesis' | 'legacy_aggregate' | 'unrecorded';
export type ReportSortField = 'created_at' | 'quality_score' | 'tool_name' | 'processing_time_ms';
export type SortOrder = 'asc' | 'desc';

export interface Report {
  id: string;
  tool_name: string;
  category: string;
  threat_type: string;
  classification_status: ClassificationStatus;
  claim_attribution_status: ClaimAttributionStatus;
  claim_attribution_version?: string | null;
  quality_score: number | null;
  created_at: string;
  processing_time_ms: number;
  status?: ReportStatus;
  generation_stage?: GenerationStage;
  generation_failure_stage?: GenerationStage | null;
  generation_error_code?: GenerationErrorCode | null;
  generation_retryable?: boolean | null;
  generation_failure?: GenerationFailureObservation | null;
  evaluation_status: EvaluationStatus;
  evaluation_error_code?: string | null;
  evaluation_attempts: number;
  evaluated_at?: string | null;
  review_status: ReviewStatus;
  analyst_disposition: AnalystDisposition;
  eligible_for_judgment: boolean;
  content_preview?: string | null;
}

export interface ReportDetail extends Report {
  markdown_content?: string;
  threat_data?: Record<string, unknown>;
  web_sources: ReportSource[];
  search_tags: string[];
  // TODO(route-provenance-v2): Remove after retained aggregate-only reports expire.
  generation_route?: ModelRouteProvenance | null;
  research_route?: ModelRouteProvenance | null;
  synthesis_route?: ModelRouteProvenance | null;
  evaluation_route?: ModelRouteProvenance | null;
  quality_assessment?: Record<string, unknown> | null;
  claim_attributions: ClaimAttributionEntry[];
  current_disposition?: AnalystDispositionEvent | null;
  disposition_history: AnalystDispositionEvent[];
}

export interface AnalystDispositionEvent {
  id: string;
  disposition: StoredAnalystDisposition;
  note?: string | null;
  evaluation_attempt: number;
  created_at: string;
  is_current: boolean;
}

export interface GenerationFailureObservation {
  schema_version: 1;
  error_code: GenerationErrorCode;
  retryable: boolean;
  stage: GenerationStage | null;
  route_attempts: ModelRouteAttempt[];
  route?: ModelRouteProvenance | null;
}

export interface ModelRouteAttempt {
  requested_model: string;
  selected_model: string;
  actual_model?: string | null;
  provider?: string | null;
  outcome: 'succeeded' | 'failed';
  error_code?: string | null;
  retryable: boolean;
}

export interface ModelRouteProvenance {
  requested_models: string[];
  requested_providers: string[];
  selected_models: string[];
  actual_models: string[];
  providers: string[];
  used_fallback: boolean;
  request_count: number;
  attempts?: ModelRouteAttempt[];
}

export interface ReportSource {
  source_id?: string | null;
  title: string;
  url: string;
  domain: string;
  access_date: string;
  relevance_score: string;
  content_type: string;
  key_findings: string;
}

export interface ClaimAttributionEntry {
  claim_class: 'threat_activity' | 'forensic_artifact' | 'detection_indicator' | 'mitigation_action';
  claim: string;
  source_ids: string[];
}

export interface ReportCreateRequest {
  tool_name: string;
  analysis_type?: 'comprehensive' | 'quick' | 'custom';
}

export interface ListReportFilters {
  query?: string;
  threat_type?: string;
  min_quality?: number;
  statuses?: ReportStatus[];
  review_statuses?: ReviewStatus[];
  analyst_dispositions?: AnalystDisposition[];
  requires_action?: boolean;
  sort_by?: ReportSortField;
  sort_order?: SortOrder;
}

export interface SearchFilters {
  query?: string;
  threat_types?: string[];
  date_range_days?: number;
  min_quality_score?: number;
  tags?: string[];
  statuses?: ReportStatus[];
  review_statuses?: ReviewStatus[];
  analyst_dispositions?: AnalystDisposition[];
  requires_action?: boolean;
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
    runs_this_week: number;
    completed_reports_this_week: number;
    failed_reports_this_week: number;
    avg_quality_score: number | null;
    scored_reports: number;
    needs_attention_reports: number;
    unresolved_reports: number;
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
    analyst_disposition: AnalystDisposition;
    eligible_for_judgment: boolean;
    status: ReportStatus;
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
    generation_failed_reports: number;
    reviewable_reports: number;
    needs_attention_reports: number;
    unresolved_reports: number;
    accepted_reports: number;
  };
  trends: {
    daily_reports: Array<{ date: string; count: number }>;
    threat_type_distribution: Array<{ threat_type: string; count: number; percentage: number }>;
    quality_score_distribution: Array<{ range: string; count: number; percentage: number }>;
    processing_time_trends: Array<{ date: string; avg_time_ms: number }>;
  };
  route_performance: Array<{
    route: 'primary' | 'fallback' | 'legacy_aggregate' | 'unrecorded';
    report_count: number;
    scored_report_count: number;
    runtime_recorded_count: number;
    avg_quality_score: number | null;
    avg_processing_time_ms: number | null;
  }>;
  generation_failure_breakdown: Array<{
    error_code: GenerationErrorCode;
    report_count: number;
    stages: Record<string, number>;
    routes: { primary: number; fallback: number; unrecorded: number };
    utc_hours: Record<string, number>;
  }>;
  recent_activity: Array<{
    id: string;
    tool_name: string;
    quality_score: number | null;
    processing_time_ms: number | null;
    created_at: string;
    threat_type?: string;
    generation_used_fallback: boolean | null;
    generation_route_scope: GenerationRouteScope;
    evaluation_status: EvaluationStatus;
    review_status: ReviewStatus;
    analyst_disposition: AnalystDisposition;
    eligible_for_judgment: boolean;
    status: ReportStatus;
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
  review_statuses?: ReviewStatus[];
  analyst_dispositions?: AnalystDisposition[];
}

export interface ActivityEvent {
  id: string;
  type: 'report_created';
  description: string;
  metadata: Record<string, unknown>;
  created_at: string;
  severity: 'success' | 'warning' | 'info';
}
