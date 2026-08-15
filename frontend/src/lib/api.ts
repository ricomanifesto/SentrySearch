/**
 * SentrySearch API Client
 * 
 * Axios-based client for communicating with the FastAPI backend.
 * Optimized for Vercel Hobby Plan deployment.
 */

import axios, { type AxiosInstance } from 'axios';
import { createClient, hasSupabaseConfig } from './supabase';
import type {
  ActivityEvent,
  AnalyticsDashboard,
  AnalyticsData,
  ExportConfig,
  ListReportFilters,
  PaginatedResponse,
  Report,
  ReportCreateRequest,
  ReportDetail,
  ReportSort,
  StoredAnalystDisposition,
  SearchFilterOptions,
  SearchFilters,
} from './api-contracts';
import { buildReportExport } from './report-export';

export type * from './api-contracts';

export class ExportHandoffEligibilityError extends Error {
  constructor(readonly blockedCount: number) {
    super('The selected handoff scope contains ineligible reports.');
    this.name = 'ExportHandoffEligibilityError';
  }
}

// API Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8001';

async function mapWithConcurrency<T, U>(
  items: T[],
  concurrency: number,
  task: (item: T) => Promise<U>,
): Promise<U[]> {
  const results = new Array<U>(items.length);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (nextIndex < items.length) {
        const index = nextIndex;
        nextIndex += 1;
        results[index] = await task(items[index]);
      }
    },
  );
  await Promise.all(workers);
  return results;
}

class SentrySearchAPI {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000, // 30 second timeout
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add auth token interceptor
    this.client.interceptors.request.use(
      async (config) => {
        const supabase = this.getSupabase();
        if (!supabase) {
          return config;
        }

        const { data: { session } } = await supabase.auth.getSession();
        if (session?.access_token) {
          config.headers.Authorization = `Bearer ${session.access_token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Request and error logging is intentionally development-only.
    if (process.env.NODE_ENV === 'development') {
      this.client.interceptors.request.use(
        (config) => {
          console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
          return config;
        },
        (error) => {
          console.error('API Request Error:', error);
          return Promise.reject(error);
        }
      );
      this.client.interceptors.response.use(
        (response) => response,
        (error) => {
          const status = error.response?.status;
          console.error(status ? `API request failed with status ${status}` : 'API request failed');
          return Promise.reject(error);
        },
      );
    }
  }

  private getSupabase() {
    if (!hasSupabaseConfig()) {
      return null;
    }

    return createClient();
  }

  // Health Check
  async healthCheck(): Promise<{ status: string; database: string }> {
    const response = await this.client.get('/api/health');
    return response.data;
  }

  // Report Management
  async listReports(
    page: number = 1,
    limit: number = 20,
    filters?: ListReportFilters
  ): Promise<PaginatedResponse<Report>> {
    const params = new URLSearchParams();
    params.append('page', page.toString());
    params.append('limit', limit.toString());
    
    if (filters?.query) params.append('query', filters.query);
    if (filters?.threat_type) params.append('threat_type', filters.threat_type);
    if (filters?.min_quality) params.append('min_quality', filters.min_quality.toString());
    filters?.statuses?.forEach((status) => params.append('status', status));
    filters?.review_statuses?.forEach((status) => params.append('review_status', status));
    filters?.analyst_dispositions?.forEach((state) => params.append('analyst_disposition', state));
    if (filters?.requires_action) params.append('requires_action', 'true');
    if (filters?.eligible_for_handoff) params.append('eligible_for_handoff', 'true');
    if (filters?.sort_by) params.append('sort_by', filters.sort_by);
    if (filters?.sort_order) params.append('sort_order', filters.sort_order);

    const response = await this.client.get(`/api/reports?${params.toString()}`);
    return response.data;
  }

  async getReport(reportId: string, includeContent: boolean = true): Promise<ReportDetail> {
    const response = await this.client.get(`/api/reports/${reportId}?include_content=${includeContent}`);
    const report = response.data as ReportDetail;
    return {
      ...report,
      generation_stage: report.generation_stage
        ?? (report.status === 'generating' ? 'queued' : report.status ?? 'completed'),
      evaluation_status: report.evaluation_status ?? (report.quality_score == null ? 'unrecorded' : 'completed'),
      evaluation_attempts: report.evaluation_attempts ?? 0,
      review_status: report.review_status ?? (report.quality_score == null ? 'needs_evaluation' : 'needs_attention'),
      analyst_disposition: report.analyst_disposition ?? 'unreviewed',
      eligible_for_judgment: report.eligible_for_judgment === true,
      eligible_for_acceptance: report.eligible_for_acceptance === true,
      eligible_for_handoff: report.eligible_for_handoff === true,
      classification_status: report.classification_status ?? 'unrecorded',
      claim_attribution_status: report.claim_attribution_status ?? 'legacy',
      evidence_admissibility_status: report.evidence_admissibility_status ?? 'unassessed',
      claim_attributions: report.claim_attributions ?? [],
      web_sources: report.web_sources ?? [],
      search_tags: report.search_tags ?? [],
      disposition_history: report.disposition_history ?? [],
    };
  }

  async createReport(request: ReportCreateRequest): Promise<{ report_id: string; status: string; message: string }> {
    // Returns immediately: the backend runs generation in the background and the
    // client polls the report until its status leaves "generating".
    const response = await this.client.post('/api/reports', request);
    return response.data;
  }

  async deleteReport(reportId: string): Promise<{ message: string }> {
    const response = await this.client.delete(`/api/reports/${reportId}`);
    return response.data;
  }

  async retryReportEvaluation(reportId: string): Promise<{ report_id: string; evaluation_status: string; message: string }> {
    const response = await this.client.post(`/api/reports/${reportId}/evaluation`);
    return response.data;
  }

  async appendReportDisposition(
    reportId: string,
    disposition: StoredAnalystDisposition,
    note?: string,
  ) {
    const response = await this.client.post(`/api/reports/${reportId}/dispositions`, {
      disposition,
      note: note?.trim() || null,
    });
    return response.data;
  }

  // Search
  async searchReports(
    filters: SearchFilters,
    page: number = 1,
    limit: number = 20,
    sort?: ReportSort
  ): Promise<PaginatedResponse<Report>> {
    const params = new URLSearchParams();
    params.append('page', page.toString());
    params.append('limit', limit.toString());
    if (sort?.sort_by) params.append('sort_by', sort.sort_by);
    if (sort?.sort_order) params.append('sort_order', sort.sort_order);

    const response = await this.client.post(`/api/search?${params.toString()}`, filters);
    return response.data;
  }

  async getSearchFilters(): Promise<SearchFilterOptions> {
    const response = await this.client.get('/api/search/filters');
    return response.data;
  }

  // Analytics
  async getDashboardAnalytics(): Promise<AnalyticsDashboard> {
    const response = await this.client.get('/api/analytics/dashboard');
    return response.data;
  }

  async getAnalytics(timeRange: string = '30d'): Promise<AnalyticsData> {
    const response = await this.client.get(`/api/analytics?time_range=${timeRange}`);
    return response.data;
  }

  async exportReports(config: ExportConfig): Promise<string> {
    const selectedIds = [...new Set(config.selected_reports ?? [])];
    const configuredMaximum = typeof config.max_reports === 'number' && Number.isFinite(config.max_reports)
      ? Math.trunc(config.max_reports)
      : 1000;
    const maxReports = Math.min(Math.max(configuredMaximum, 1), 1000);
    let reports: ReportDetail[];

    if (selectedIds.length > 0) {
      reports = await mapWithConcurrency(
        selectedIds.slice(0, maxReports),
        8,
        (reportId) => this.getReport(reportId, config.include_content),
      );
      const blockedCount = reports.filter((report) => !report.eligible_for_handoff).length;
      if (blockedCount > 0) {
        throw new ExportHandoffEligibilityError(blockedCount);
      }
    } else {
      const summaries: Report[] = [];
      let page = 1;
      while (summaries.length < maxReports) {
        const pageSize = 100;
        const response = await this.searchReports(
          {
            threat_types: config.threat_types,
            date_range_days: config.date_range_days,
            min_quality_score: config.min_quality_score,
            review_statuses: config.review_statuses,
            analyst_dispositions: config.analyst_dispositions,
            eligible_for_handoff: true,
          },
          page,
          pageSize,
          { sort_by: 'created_at', sort_order: 'desc' },
        );
        const remaining = maxReports - summaries.length;
        summaries.push(...response.reports.slice(0, remaining));
        if (page >= response.pagination.pages || response.reports.length === 0) break;
        page += 1;
      }
      const needsDetails = config.include_content || config.include_tags || config.include_sources || config.include_metadata;
      reports = needsDetails
        ? await mapWithConcurrency(
            summaries,
            8,
            (report) => this.getReport(report.id, config.include_content),
          )
        : summaries.map((report) => ({
            ...report,
            web_sources: [],
            search_tags: [],
            claim_attributions: [],
            disposition_history: [],
          }));
      if (reports.some((report) => !report.eligible_for_handoff)) {
        throw new ExportHandoffEligibilityError(1);
      }
    }

    return buildReportExport(reports, config);
  }

  async getActivities(): Promise<ActivityEvent[]> {
    const analytics = await this.getDashboardAnalytics();
    return analytics.recent_activity.map((report) => ({
      id: report.id,
      type: 'report_created',
      description: report.status === 'failed'
        ? `Generation failed for ${report.tool_name}`
        : report.status === 'generating'
          ? `Generating ${report.tool_name}`
          : `Completed ${report.tool_name}`,
      metadata: {
        tool_name: report.tool_name,
        quality_score: report.quality_score,
        review_status: report.review_status,
      },
      created_at: report.created_at,
      severity: report.review_status === 'reviewable'
        ? 'success'
        : report.review_status === 'generating' || report.review_status === 'evaluation_pending'
          ? 'info'
          : 'warning',
    }));
  }
}

// Create singleton instance
export const api = new SentrySearchAPI();

// Export for use in React Query
export default api;
