"use client";

import Link from "next/link";
import type { ReactNode } from "react";

type AuthFrameProps = {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  footer: ReactNode;
};

const trustSignals = [
  {
    label: "Source-first analysis",
    description: "Generated intelligence stays tied to the evidence that supports it.",
  },
  {
    label: "Saved review queue",
    description: "Return to prior reports, confidence notes, and investigation context.",
  },
  {
    label: "Private workspace",
    description: "Your account keeps report generation and saved intelligence to you.",
  },
];

export function AuthFrame({
  eyebrow,
  title,
  description,
  children,
  footer,
}: AuthFrameProps) {
  return (
    <div
      data-surface="auth-entry"
      className="min-h-[calc(100vh-4rem)] bg-[var(--surface-0)] px-4 py-10 text-zinc-950 sm:px-6 sm:py-14 lg:px-8"
    >
      <div className="mx-auto grid w-full max-w-6xl gap-10 lg:min-h-[calc(100vh-8rem)] lg:grid-cols-[minmax(0,1fr)_minmax(380px,440px)] lg:items-center lg:gap-16">
        <section className="fade-up space-y-8">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-blue-700">
              SentrySearch
            </p>
            <h1 className="mt-3 text-balance text-4xl font-semibold leading-[1.1] tracking-tight text-zinc-950 sm:mt-4 sm:text-5xl">
              Source-backed threat intelligence
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-zinc-600">
              Generate threat reports, inspect the source context behind each
              finding, and keep saved intelligence organized in one workspace.
            </p>
          </div>

          <div data-testid="auth-trust-signals" className="grid gap-3 sm:grid-cols-3">
            {trustSignals.map((signal) => (
              <div
                key={signal.label}
                className="rounded-xl border border-zinc-200 bg-white p-4"
              >
                <h2 className="text-sm font-semibold text-zinc-950">
                  {signal.label}
                </h2>
                <p className="mt-1.5 text-sm leading-6 text-zinc-600">
                  {signal.description}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section
          aria-labelledby="auth-panel-title"
          className="fade-up fade-up-1 rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm sm:p-8"
        >
          <p className="text-sm font-medium text-zinc-500">{eyebrow}</p>
          <h2
            id="auth-panel-title"
            className="mt-3 text-2xl font-semibold tracking-tight text-zinc-950"
          >
            {title}
          </h2>
          <p className="mt-3 text-sm leading-6 text-zinc-600">{description}</p>

          <div className="mt-8">{children}</div>

          <div className="mt-6 border-t border-zinc-200 pt-5 text-sm text-zinc-600">
            {footer}
          </div>
        </section>
      </div>
    </div>
  );
}

type AuthNoticeProps = {
  title: string;
  description: string;
  actionHref: string;
  actionLabel: string;
};

export function AuthNotice({
  title,
  description,
  actionHref,
  actionLabel,
}: AuthNoticeProps) {
  return (
    <AuthFrame
      eyebrow="Account verification"
      title={title}
      description={description}
      footer={
        <Link
          href={actionHref}
          className="font-medium text-blue-700 underline-offset-4 hover:underline"
        >
          {actionLabel}
        </Link>
      }
    >
      <div className="rounded-xl border border-blue-200 bg-blue-50 px-4 py-4 text-sm leading-6 text-blue-900">
        Your workspace will open after the email confirmation link is complete.
      </div>
    </AuthFrame>
  );
}
