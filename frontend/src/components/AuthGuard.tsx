/**
 * Authentication guard component that redirects unauthenticated users to login
 */

'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { AuthFrame } from '@/components/auth/AuthFrame';

interface AuthGuardProps {
  children: React.ReactNode;
  requireAuth?: boolean;
}

export function AuthGuard({ children, requireAuth = true }: AuthGuardProps) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && requireAuth && !user) {
      const nextPath = `${window.location.pathname}${window.location.search}${window.location.hash}`;
      router.replace(`/auth/signin?next=${encodeURIComponent(nextPath)}`);
    }
  }, [user, loading, requireAuth, router]);

  if (loading) {
    return (
      <div
        className="min-h-[calc(100vh-4rem)] bg-[var(--surface-0)] px-4 py-10 text-zinc-950 sm:px-6 lg:px-8"
        role="status"
        aria-label="Checking workspace access"
      >
        <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-3xl items-center justify-center">
          <div className="w-full rounded-xl border border-zinc-200 bg-white px-6 py-8 text-center shadow-sm sm:px-10">
            <div className="mx-auto mb-5 h-10 w-10 animate-spin rounded-full border-2 border-zinc-300 border-t-blue-600" />
            <h1 className="text-2xl font-semibold text-zinc-950">Checking workspace access</h1>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-zinc-600">
              Verifying whether this browser can open saved intelligence and report review surfaces.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (requireAuth && !user) {
    return (
      <AuthFrame
        eyebrow="Workspace boundary"
        title="Sign in to review saved intelligence"
        description="Report details, saved searches, and generation history stay behind your SentrySearch account."
        footer={
          <button
            type="button"
            onClick={() => {
              const nextPath = `${window.location.pathname}${window.location.search}${window.location.hash}`;
              router.replace(`/auth/signin?next=${encodeURIComponent(nextPath)}`);
            }}
            className="font-medium text-blue-700 underline-offset-4 hover:underline"
          >
            Continue to analyst access
          </button>
        }
      >
        <div className="rounded-xl border border-blue-200 bg-blue-50 px-4 py-4 text-sm leading-6 text-blue-900">
          Your account session is required before this workspace can show report records or saved intelligence.
        </div>
      </AuthFrame>
    );
  }

  return <>{children}</>;
}
