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
      router.push('/auth/signin');
    }
  }, [user, loading, requireAuth, router]);

  if (loading) {
    return (
      <div
        className="min-h-[calc(100vh-4rem)] bg-[#f7f7f3] px-4 py-10 text-[#171915] sm:px-6 lg:px-8"
        role="status"
        aria-label="Checking workspace access"
      >
        <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-3xl items-center justify-center">
          <div className="w-full border border-[#d8d9ce] bg-white px-6 py-8 text-center shadow-[0_18px_50px_rgba(23,25,21,0.08)] sm:px-10">
            <div className="mx-auto mb-5 h-10 w-10 animate-spin border-2 border-[#c8c9bd] border-t-[#20231f]" />
            <h1 className="text-2xl font-semibold text-[#171915]">Checking workspace access</h1>
            <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-[#5d6458]">
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
            onClick={() => router.push('/auth/signin')}
            className="font-medium text-[#4d5f24] underline-offset-4 hover:underline"
          >
            Continue to analyst access
          </button>
        }
      >
        <div className="border border-[#d9dfca] bg-[#f8fbf2] px-4 py-4 text-sm leading-6 text-[#4a542f]">
          Your account session is required before this workspace can show report records or saved intelligence.
        </div>
      </AuthFrame>
    );
  }

  return <>{children}</>;
}
