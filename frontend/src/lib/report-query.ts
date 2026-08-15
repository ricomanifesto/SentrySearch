import type {
  ListReportFilters,
  ReportSort,
  ReportSortField,
  ReviewStatus,
  SearchFilters,
  SortOrder,
} from './api-contracts';

export interface ReportQueryState {
  query: string;
  threatType: string;
  minQuality: string;
  dateRangeDays: string;
  reviewState: string;
  sortBy: ReportSortField;
  sortOrder: SortOrder;
}

export const defaultReportQuery: Readonly<ReportQueryState> = Object.freeze({
  query: '',
  threatType: '',
  minQuality: '',
  dateRangeDays: '',
  reviewState: 'actionable',
  sortBy: 'created_at',
  sortOrder: 'desc',
});

export const qualityFilterOptions = [
  { value: '', label: 'Any quality' },
  { value: '4.5', label: '4.50+ Excellent' },
  { value: '4.0', label: '4.00+ Good' },
  { value: '3.5', label: '3.50+ Acceptable' },
  { value: '3.0', label: '3.00+ Needs Improvement' },
];

export const dateRangeFilterOptions = [
  { value: '', label: 'Any time' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last year' },
];

export const reviewStateFilterOptions = [
  { value: 'actionable', label: 'Action needed' },
  { value: 'reviewable', label: 'Reviewable' },
  { value: 'needs_attention', label: 'Needs attention' },
  { value: 'needs_evaluation', label: 'Needs evaluation' },
  { value: 'generation_failed', label: 'Generation failed' },
  { value: 'generating', label: 'Generating' },
  { value: 'all', label: 'All history' },
];

export function reviewStatusesForState(value: string): ReviewStatus[] | undefined {
  if (value === 'actionable') return ['generation_failed', 'needs_attention', 'needs_evaluation'];
  if (value === 'all') return undefined;
  return reviewStateFilterOptions.some((option) => option.value === value)
    ? [value as ReviewStatus]
    : ['generation_failed', 'needs_attention', 'needs_evaluation'];
}

export const reportSortOptions = [
  { value: 'created_at', label: 'Date created' },
  { value: 'quality_score', label: 'Quality score' },
  { value: 'tool_name', label: 'Target name' },
  { value: 'processing_time_ms', label: 'Processing time' },
] satisfies Array<{ value: ReportSortField; label: string }>;

export const sortOrderOptions = [
  { value: 'desc', label: 'Descending' },
  { value: 'asc', label: 'Ascending' },
] satisfies Array<{ value: SortOrder; label: string }>;

export function toListReportFilters(state: ReportQueryState): ListReportFilters {
  return {
    query: state.query || undefined,
    threat_type: state.threatType || undefined,
    min_quality: state.minQuality ? Number.parseFloat(state.minQuality) : undefined,
    review_statuses: reviewStatusesForState(state.reviewState),
    sort_by: state.sortBy,
    sort_order: state.sortOrder,
  };
}

export function toSearchFilters(state: ReportQueryState): SearchFilters {
  return {
    query: state.query || undefined,
    threat_types: state.threatType ? [state.threatType] : undefined,
    min_quality_score: state.minQuality ? Number.parseFloat(state.minQuality) : undefined,
    date_range_days: state.dateRangeDays ? Number.parseInt(state.dateRangeDays, 10) : undefined,
    review_statuses: reviewStatusesForState(state.reviewState),
  };
}

export function toReportSort(state: ReportQueryState): ReportSort {
  return { sort_by: state.sortBy, sort_order: state.sortOrder };
}

export function countActiveReportFilters(state: ReportQueryState): number {
  return [state.query, state.threatType, state.minQuality, state.dateRangeDays].filter(Boolean).length
    + (state.reviewState !== defaultReportQuery.reviewState ? 1 : 0);
}

export function reportQueryFromSearchParams(params: URLSearchParams): ReportQueryState {
  const sortBy = params.get('sort_by');
  const sortOrder = params.get('sort_order');
  return {
    query: params.get('query') || '',
    threatType: params.get('threat_type') || '',
    minQuality: params.get('min_quality') || '',
    dateRangeDays: params.get('date_range') || '',
    reviewState: reviewStateFilterOptions.some((option) => option.value === params.get('review_state'))
      ? params.get('review_state') as string
      : defaultReportQuery.reviewState,
    sortBy: reportSortOptions.some((option) => option.value === sortBy)
      ? sortBy as ReportSortField
      : defaultReportQuery.sortBy,
    sortOrder: sortOrder === 'asc' || sortOrder === 'desc'
      ? sortOrder
      : defaultReportQuery.sortOrder,
  };
}

export function reportQuerySearchParams(state: ReportQueryState, page = 1): URLSearchParams {
  const params = new URLSearchParams();
  if (state.query) params.set('query', state.query);
  if (state.threatType) params.set('threat_type', state.threatType);
  if (state.minQuality) params.set('min_quality', state.minQuality);
  if (state.dateRangeDays) params.set('date_range', state.dateRangeDays);
  if (state.reviewState !== defaultReportQuery.reviewState) params.set('review_state', state.reviewState);
  if (state.sortBy !== defaultReportQuery.sortBy) params.set('sort_by', state.sortBy);
  if (state.sortOrder !== defaultReportQuery.sortOrder) params.set('sort_order', state.sortOrder);
  if (page > 1) params.set('page', String(page));
  return params;
}

export function getQualityLabel(score: number | null): string {
  if (score == null) return 'Not scored';
  if (score >= 4.5) return 'Excellent';
  if (score >= 4) return 'Good';
  if (score >= 3.5) return 'Acceptable';
  if (score >= 3) return 'Needs Improvement';
  return 'Poor';
}

export function formatTaxonomyLabel(value: string): string {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}
