/**
 * SentrySearch API Client
 * 
 * Axios-based client for communicating with the FastAPI backend.
 * Optimized for Vercel Hobby Plan deployment.
 */

import axios, { AxiosInstance } from 'axios';
import { createClient } from './supabase';

// Types
export interface Report {
  id: string;
  tool_name: string;
  category: string;
  threat_type: string;
  quality_score: number;
  created_at: string;
  processing_time_ms: number;
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

export interface SearchFilters {
  query?: string;
  threat_types?: string[];
  date_range_days?: number;
  min_quality_score?: number;
  tags?: string[];
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

// API Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

class SentrySearchAPI {
  private client: AxiosInstance;
  private supabase = createClient();

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
        const { data: { session } } = await this.supabase.auth.getSession();
        if (session?.access_token) {
          config.headers.Authorization = `Bearer ${session.access_token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Request interceptor for logging (development only)
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
    }

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response) {
          // Server responded with error status
          console.error(`API Error ${error.response.status}:`, error.response.data);
        } else if (error.request) {
          // Request made but no response received
          console.error('API Network Error:', error.message);
        } else {
          // Something else happened
          console.error('API Error:', error.message);
        }
        return Promise.reject(error);
      }
    );
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
    filters?: {
      query?: string;
      threat_type?: string;
      min_quality?: number;
    }
  ): Promise<PaginatedResponse<Report>> {
    const params = new URLSearchParams();
    params.append('page', page.toString());
    params.append('limit', limit.toString());
    
    if (filters?.query) params.append('query', filters.query);
    if (filters?.threat_type) params.append('threat_type', filters.threat_type);
    if (filters?.min_quality) params.append('min_quality', filters.min_quality.toString());

    const response = await this.client.get(`/api/reports?${params.toString()}`);
    return response.data;
  }

  async getReport(reportId: string, includeContent: boolean = true): Promise<ReportDetail> {
    const response = await this.client.get(`/api/reports/${reportId}?include_content=${includeContent}`);
    return response.data;
  }

  async createReport(request: ReportCreateRequest): Promise<{ report_id: string; status: string; message: string }> {
    // Use longer timeout for report generation (30 minutes)
    const response = await this.client.post('/api/reports', request, {
      timeout: 1800000, // 30 minutes
    });
    return response.data;
  }

  async deleteReport(reportId: string): Promise<{ message: string }> {
    const response = await this.client.delete(`/api/reports/${reportId}`);
    return response.data;
  }

  // Search
  async searchReports(
    filters: SearchFilters,
    page: number = 1,
    limit: number = 20
  ): Promise<PaginatedResponse<Report>> {
    const params = new URLSearchParams();
    params.append('page', page.toString());
    params.append('limit', limit.toString());

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

  // Admin endpoints (mock data for now)
  async getUsers(): Promise<Record<string, unknown>[]> {
    // Mock data until backend implementation
    return [
      {
        id: '1',
        username: 'admin',
        email: 'admin@sentrysearch.com',
        role: 'admin',
        status: 'active',
        last_login: new Date().toISOString(),
        created_at: new Date(Date.now() - 86400000).toISOString(),
        reports_count: 25,
        api_usage_count: 150,
      },
      {
        id: '2',
        username: 'analyst1',
        email: 'analyst@sentrysearch.com',
        role: 'analyst',
        status: 'active',
        last_login: new Date(Date.now() - 3600000).toISOString(),
        created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
        reports_count: 12,
        api_usage_count: 89,
      },
    ];
  }

  async getSystemStatus(): Promise<Record<string, unknown>> {
    // Mock data until backend implementation
    return {
      api_health: 'healthy',
      database_health: 'healthy',
      storage_health: 'healthy',
      active_users: 3,
      total_requests_24h: 1247,
      error_rate_24h: 0.02,
      avg_response_time_ms: 234,
    };
  }

  // User management methods removed - not currently needed

  // Export functionality
  async exportReports(config: Record<string, unknown>): Promise<string> {
    // Mock implementation - generate sample export data
    const timestamp = new Date().toISOString();
    
    switch (config.format) {
      case 'json':
        return JSON.stringify({
          export_metadata: {
            timestamp,
            format: 'json',
            total_reports: 5,
            filters: config
          },
          reports: [
            {
              id: '1',
              tool_name: 'ShadowPad',
              quality_score: 4.2,
              created_at: timestamp,
              content: config.include_content ? 'Sample threat intelligence content...' : undefined
            }
          ]
        }, null, 2);
        
      case 'csv':
        return `id,tool_name,quality_score,created_at,threat_type\n1,ShadowPad,4.2,${timestamp},malware\n2,Cobalt Strike,3.8,${timestamp},attack_tool`;
        
      case 'markdown':
        return `# Threat Intelligence Export\n\nGenerated: ${timestamp}\n\n## Reports\n\n### ShadowPad\n- Quality Score: 4.2\n- Created: ${timestamp}\n\nSample threat intelligence content...`;
        
      default:
        return 'Export data';
    }
  }

  // Activity tracking
  async getActivities(): Promise<Record<string, unknown>[]> {
    // Mock implementation
    return [];
  }
}

// Create singleton instance
export const api = new SentrySearchAPI();

// Export for use in React Query
export default api;