'use client';

import React from 'react';
import {
  CircleStackIcon,
  LockClosedIcon,
  ServerStackIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline';

import { AuthGuard } from '@/components/AuthGuard';
import { Badge } from '@/components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';

const readinessAreas = [
  {
    title: 'Workspace access review',
    description:
      'Confirm that saved reports, review history, and account context remain scoped to authenticated workspace access.',
    status: 'Protected',
    icon: ShieldCheckIcon,
  },
  {
    title: 'Deployment posture',
    description:
      'Track which operational controls still belong in server configuration before exposing them in the browser.',
    status: 'Server-owned',
    icon: ServerStackIcon,
  },
  {
    title: 'Report governance',
    description:
      'Reserve space for retention, review queue, and source-transparency controls once the backend contract exists.',
    status: 'Contract pending',
    icon: CircleStackIcon,
  },
];

const boundaryNotes = [
  'Read-only until admin APIs are wired',
  'No browser-local provider keys',
  'No destructive workspace actions',
];

export default function AdminPage() {
  return (
    <AuthGuard>
      <div className="min-h-screen overflow-x-hidden bg-slate-50 py-6 sm:py-10">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
          <div className="mb-8 max-w-3xl">
            <Badge variant="warning" size="sm" className="mb-3 rounded-md">
              Control plane review
            </Badge>
            <h1 className="text-2xl font-semibold leading-tight tracking-tight text-slate-950 sm:text-4xl">
              Admin readiness center
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
              Review the operational boundaries that need explicit backend
              contracts before SentrySearch exposes administrator controls.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Card className="min-w-0 border-slate-200 shadow-sm lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-950">
                  <LockClosedIcon className="h-5 w-5 text-slate-700" />
                  Administrative surface status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  {boundaryNotes.map((note) => (
                    <div
                      key={note}
                      className="min-w-0 border border-slate-200 bg-slate-50 p-4"
                    >
                      <p className="text-sm font-semibold text-slate-950">
                        {note}
                      </p>
                    </div>
                  ))}
                </div>
                <div className="mt-5 border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">
                  This route is intentionally non-mutating. It documents the
                  admin control areas that require authenticated backend
                  ownership before they become interactive.
                </div>
              </CardContent>
            </Card>

            <Card className="min-w-0 border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle className="text-slate-950">Boundary owner</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 text-sm leading-6">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Auth state
                    </p>
                    <p className="mt-1 text-slate-950">Required for review</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Configuration
                    </p>
                    <p className="mt-1 text-slate-950">Server-side only</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Workspace actions
                    </p>
                    <p className="mt-1 text-slate-950">Unavailable here</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid min-w-0 grid-cols-1 gap-4 lg:col-span-3 lg:grid-cols-3">
              {readinessAreas.map((area) => {
                const Icon = area.icon;
                return (
                  <Card
                    key={area.title}
                    className="min-w-0 border-slate-200 shadow-sm"
                  >
                    <CardHeader>
                      <div className="mb-3 flex h-10 w-10 items-center justify-center bg-slate-100">
                        <Icon className="h-5 w-5 text-slate-700" />
                      </div>
                      <CardTitle className="text-slate-950">
                        {area.title}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm leading-6 text-slate-600">
                        {area.description}
                      </p>
                      <Badge
                        variant="info"
                        size="sm"
                        className="mt-4 rounded-md"
                      >
                        {area.status}
                      </Badge>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}
