"use client"

import { useAuth } from "@/contexts/AuthContext"
import { AuthGuard } from "@/components/AuthGuard"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card"
import { SurfaceHeader } from "@/components/ui/SurfaceHeader"
import {
  IdentificationIcon,
  ServerStackIcon,
  ShieldCheckIcon,
} from "@heroicons/react/24/outline"

export default function Settings() {
  const { user } = useAuth()
  const userMetadata = user?.user_metadata || {}
  const displayName =
    typeof userMetadata.name === "string" && userMetadata.name.trim()
      ? userMetadata.name
      : "Unavailable in this session"
  const email = user?.email || "Unavailable in this session"

  return (
    <AuthGuard>
      <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
          <SurfaceHeader
            eyebrow="Workspace boundary"
            title="Workspace access controls"
            description="Review the account context and generation policy that govern saved intelligence in this browser session."
          />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Card className="min-w-0 border-slate-200 shadow-sm lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-950">
                  <IdentificationIcon className="h-5 w-5 text-slate-700" />
                  Workspace identity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="min-w-0 border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Display name
                    </p>
                    <p className="mt-2 break-words text-sm font-medium text-slate-950">
                      {displayName}
                    </p>
                  </div>
                  <div className="min-w-0 border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Work email
                    </p>
                    <p className="mt-2 break-words text-sm font-medium text-slate-950">
                      {email}
                    </p>
                  </div>
                </div>
                <div className="mt-5 border border-blue-200 bg-blue-50 p-4 text-sm leading-6 text-blue-900">
                  This identity is read from the active authenticated session.
                  SentrySearch uses it to keep saved reports and review history
                  scoped to the current workspace.
                </div>
              </CardContent>
            </Card>

            <Card className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-950">
                  <ShieldCheckIcon className="h-5 w-5 text-slate-700" />
                  Access posture
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 text-sm leading-6 text-slate-600">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Account boundary
                    </p>
                    <p className="mt-1 text-slate-950">
                      Required for saved intelligence
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Report storage
                    </p>
                    <p className="mt-1 text-slate-950">
                      Scoped to authenticated workspace access
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="min-w-0 border-slate-200 shadow-sm lg:col-span-3">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-950">
                  <ServerStackIcon className="h-5 w-5 text-slate-700" />
                  Generation policy
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <div className="min-w-0 border border-slate-200 bg-white p-4">
                    <p className="text-sm font-semibold text-slate-950">
                      Server-side gateway
                    </p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      Report generation uses the configured backend model path for this deployment.
                    </p>
                  </div>
                  <div className="min-w-0 border border-slate-200 bg-white p-4">
                    <p className="text-sm font-semibold text-slate-950">
                      Provider keys remain server-side
                    </p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      This page does not collect user-level provider credentials or expose deployment secrets.
                    </p>
                  </div>
                  <div className="min-w-0 border border-slate-200 bg-white p-4">
                    <p className="text-sm font-semibold text-slate-950">
                      Policy changes
                    </p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      Generation settings are controlled through backend configuration rather than browser-local form fields.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </AuthGuard>
  )
}
