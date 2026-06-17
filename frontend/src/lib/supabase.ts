/**
 * Supabase client configuration for SentrySearch
 */

import { createBrowserClient } from '@supabase/ssr'

// Browser client for client-side operations
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}

// Database type definitions (will be generated from Supabase)
export type Database = {
  public: {
    Tables: {
      user_profiles: {
        Row: {
          id: string
          preferences: Record<string, unknown>
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          preferences?: Record<string, unknown>
        }
        Update: {
          preferences?: Record<string, unknown>
        }
      }
      reports: {
        Row: {
          id: string
          user_id: string | null
          tool_name: string
          category: string
          threat_type: string
          quality_score: number | null
          processing_time_ms: number | null
          markdown_content: string | null
          threat_data: Record<string, unknown> | null
          search_tags: string[]
          created_at: string
          updated_at: string
        }
      }
    }
  }
}
