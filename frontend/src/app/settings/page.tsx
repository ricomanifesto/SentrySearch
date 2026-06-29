"use client"

import { useAuth } from "@/contexts/AuthContext"
import { AuthGuard } from "@/components/AuthGuard"

const generationPolicy = [
  {
    title: "Server-side gateway",
    description: "Report generation uses the configured backend model path for this deployment.",
  },
  {
    title: "Provider keys stay server-side",
    description: "This page does not collect user-level provider credentials or expose deployment secrets.",
  },
  {
    title: "Policy changes",
    description: "Generation settings are controlled through backend configuration, not browser-local form fields.",
  },
]

export default function Settings() {
  const { user } = useAuth()
  const userMetadata = user?.user_metadata || {}
  const displayName =
    typeof userMetadata.name === "string" && userMetadata.name.trim()
      ? userMetadata.name
      : "Unavailable in this session"
  const email = user?.email || "Unavailable in this session"

  const identity = [
    { label: "Display name", value: displayName },
    { label: "Work email", value: email },
  ]
  const accessPosture = [
    { label: "Account boundary", value: "Required for saved intelligence" },
    { label: "Report storage", value: "Scoped to authenticated workspace access" },
  ]

  return (
    <AuthGuard>
      <main data-surface="settings-workspace" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-5xl px-6 py-12 lg:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">Workspace</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Workspace access</h1>
            <p className="mt-4 text-lg leading-8 text-zinc-600">
              The account context and generation policy that govern saved
              intelligence in this session.
            </p>
          </div>

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-3">
            <section className="rounded-xl border border-zinc-200 bg-white p-5 lg:col-span-2">
              <h2 className="text-base font-semibold text-zinc-950">Workspace identity</h2>
              <dl className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                {identity.map((row) => (
                  <div key={row.label} className="min-w-0 rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4">
                    <dt className="text-sm text-zinc-500">{row.label}</dt>
                    <dd className="mt-2 break-words text-sm font-medium text-zinc-950">{row.value}</dd>
                  </div>
                ))}
              </dl>
              <p className="mt-5 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm leading-6 text-blue-900">
                This identity is read from the active authenticated session. SentrySearch
                uses it to keep saved reports and review history scoped to this workspace.
              </p>
            </section>

            <section className="rounded-xl border border-zinc-200 bg-white p-5">
              <h2 className="text-base font-semibold text-zinc-950">Access posture</h2>
              <dl className="mt-4 space-y-4">
                {accessPosture.map((row) => (
                  <div key={row.label}>
                    <dt className="text-sm text-zinc-500">{row.label}</dt>
                    <dd className="mt-1 text-sm font-medium text-zinc-950">{row.value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <section className="rounded-xl border border-zinc-200 bg-white p-5 lg:col-span-3">
              <h2 className="text-base font-semibold text-zinc-950">Generation policy</h2>
              <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
                {generationPolicy.map((item) => (
                  <div key={item.title} className="min-w-0 rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4">
                    <p className="text-sm font-medium text-zinc-950">{item.title}</p>
                    <p className="mt-2 text-sm leading-6 text-zinc-600">{item.description}</p>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      </main>
    </AuthGuard>
  )
}
