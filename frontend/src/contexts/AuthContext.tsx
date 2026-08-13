'use client'

import React, { createContext, useContext, useEffect, useState } from 'react'
import { User } from '@supabase/supabase-js'
import { createClient, hasSupabaseConfig } from '@/lib/supabase'

type AuthContextType = {
  user: User | null
  loading: boolean
  signUp: (email: string, password: string, name: string) => Promise<{ error: Error | null }>
  signIn: (email: string, password: string) => Promise<{ error: Error | null }>
  requestPasswordReset: (email: string) => Promise<{ error: Error | null }>
  updatePassword: (password: string) => Promise<{ error: Error | null }>
  signOut: () => Promise<{ error: Error | null }>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [supabase] = useState(() => (hasSupabaseConfig() ? createClient() : null))
  const [loading, setLoading] = useState(() => supabase !== null)

  useEffect(() => {
    if (!supabase) {
      return
    }

    // Get initial session
    const getInitialSession = async () => {
      const { data: { session } } = await supabase.auth.getSession()
      setUser(session?.user ?? null)
      setLoading(false)
    }

    getInitialSession()

    // Listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        setUser(session?.user ?? null)
        setLoading(false)
      }
    )

    return () => subscription.unsubscribe()
  }, [supabase])

  const signUp = async (email: string, password: string, name: string) => {
    if (!supabase) {
      return { error: new Error('Authentication is not configured') }
    }

    try {
      const { error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: `${window.location.origin}/auth/signin`,
          data: {
            name,
          },
        },
      })
      return { error }
    } catch (error) {
      return { error: error as Error }
    }
  }

  const signIn = async (email: string, password: string) => {
    if (!supabase) {
      return { error: new Error('Authentication is not configured') }
    }

    try {
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
      })
      return { error }
    } catch (error) {
      return { error: error as Error }
    }
  }

  const signOut = async () => {
    if (!supabase) {
      return { error: new Error('Authentication is not configured') }
    }

    try {
      const { error } = await supabase.auth.signOut()
      return { error }
    } catch (error) {
      return { error: error as Error }
    }
  }

  const requestPasswordReset = async (email: string) => {
    if (!supabase) {
      return { error: new Error('Authentication is not configured') }
    }

    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/auth/reset-password`,
      })
      return { error }
    } catch (error) {
      return { error: error as Error }
    }
  }

  const updatePassword = async (password: string) => {
    if (!supabase) {
      return { error: new Error('Authentication is not configured') }
    }

    try {
      const { error } = await supabase.auth.updateUser({ password })
      return { error }
    } catch (error) {
      return { error: error as Error }
    }
  }

  const value = {
    user,
    loading,
    signUp,
    signIn,
    requestPasswordReset,
    updatePassword,
    signOut,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
