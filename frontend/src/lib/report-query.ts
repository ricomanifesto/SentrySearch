import type {
  ListReportFilters,
  ReportSort,
  ReportSortField,
  SearchFilters,
  SortOrder,
} from './api-contracts';

export interface ReportQueryState {
  query: string;
  threatType: string;
  minQuality: string;
  dateRangeDays: string;
  sortBy: ReportSortField;
  sortOrder: SortOrder;
}

export const defaultReportQuery: Readonly<ReportQueryState> = Object.freeze({
  query: '',
  threatType: '',
  minQuality: '',
  dateRangeDays: '',
  sortBy: 'created_at',
  sortOrder: 'desc',
});

export const qualityFilterOptions = [
  { value: '', label: 'Any quality' },
  { value: '4.0', label: '4.0+ high confidence' },
  { value: '3.0', label: '3.0+ reviewable' },
  { value: '2.0', label: '2.0+ needs review' },
  { value: '1.0', label: '1.0+ low confidence' },
];

export const dateRangeFilterOptions = [
  { value: '', label: 'Any time' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '90', label: 'Last 90 days' },
  { value: '365', label: 'Last year' },
];

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
  };
}

export function toReportSort(state: ReportQueryState): ReportSort {
  return { sort_by: state.sortBy, sort_order: state.sortOrder };
}

export function countActiveReportFilters(state: ReportQueryState): number {
  return [state.query, state.threatType, state.minQuality, state.dateRangeDays].filter(Boolean).length;
}

export function getQualityLabel(score: number): string {
  if (score >= 4) return 'High confidence';
  if (score >= 3) return 'Reviewable';
  if (score >= 2) return 'Needs review';
  return 'Low confidence';
}

export function formatTaxonomyLabel(value: string): string {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}
