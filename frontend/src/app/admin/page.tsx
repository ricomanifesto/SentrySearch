'use client';

import React from 'react';

import { AuthGuard } from '@/components/AuthGuard';

const readinessAreas = [
  {
    title: 'Workspace access review',
    description: 'Confirm that saved reports, review history, and account context remain scoped to authenticated workspace access.',
    status: 'Protected',
  },
  {
    title: 'Deployment posture',
    description: 'Track which operational controls still belong in server configuration before exposing them in the browser.',
    status: 'Server-owned',
  },
  {
    title: 'Report governance',
    description: 'Reserve space for retention, review queue, and source-transparency controls once the backend contract exists.',
    status: 'Contract pending',
  },
];

const boundaryNotes = [
  'Read-only until admin APIs are wired',
  'No browser-local provider keys',
  'No destructive workspace actions',
];

const boundaryOwner = [
  { label: 'Auth state', value: 'Required for review' },
  { label: 'Configuration', value: 'Server-side only' },
  { label: 'Workspace actions', value: 'Unavailable here' },
];

export default function AdminPage() {
  return (
    <AuthGuard>
      <main data-surface="admin-readiness" className="overflow-x-hidden bg-[var(--surface-0)]">
        <div className="mx-auto max-w-6xl px-6 py-12 lg:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">Control plane</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-950">Admin readiness center</h1>
            <p className="mt-4 text-lg leading-8 text-zinc-600">
              The operational boundaries that need explicit backend contracts before
              SentrySearch exposes administrator controls.
            </p>
          </div>

          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-3">
            <section className="rounded-xl border border-zinc-200 bg-white p-5 lg:col-span-2">
              <h2 className="text-base font-semibold text-zinc-950">Administrative surface status</h2>
              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                {boundaryNotes.map((note) => (
                  <div key={note} className="min-w-0 rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4">
                    <p className="text-sm font-medium text-zinc-950">{note}</p>
                  </div>
                ))}
              </div>
              <p className="mt-5 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">
                This route is intentionally non-mutating. It documents the admin control
                areas that require authenticated backend ownership before they become interactive.
              </p>
            </section>

            <section className="rounded-xl border border-zinc-200 bg-white p-5">
              <h2 className="text-base font-semibold text-zinc-950">Boundary owner</h2>
              <dl className="mt-4 space-y-4">
                {boundaryOwner.map((row) => (
                  <div key={row.label}>
                    <dt className="text-sm text-zinc-500">{row.label}</dt>
                    <dd className="mt-1 text-sm font-medium text-zinc-950">{row.value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <div className="grid min-w-0 grid-cols-1 gap-4 lg:col-span-3 lg:grid-cols-3">
              {readinessAreas.map((area) => (
                <section key={area.title} className="min-w-0 rounded-xl border border-zinc-200 bg-white p-5">
                  <h3 className="text-base font-semibold text-zinc-950">{area.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-zinc-600">{area.description}</p>
                  <span className="mt-4 inline-block rounded-md bg-blue-50 px-2 py-1 text-sm font-medium text-blue-700">{area.status}</span>
                </section>
              ))}
            </div>
          </div>
        </div>
      </main>
    </AuthGuard>
  );
}
