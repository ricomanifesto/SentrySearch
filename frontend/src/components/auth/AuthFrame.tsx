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
    description: "Keep generated intelligence tied to the evidence that supports it.",
  },
  {
    label: "Saved review queue",
    description: "Return to prior reports, confidence notes, and investigation context.",
  },
  {
    label: "Private workspace",
    description: "Account access gates report generation and saved intelligence workflows.",
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
    <div className="min-h-[calc(100vh-4rem)] bg-[#f7f7f3] px-4 py-8 text-[#171915] sm:px-6 lg:px-8">
      <div className="mx-auto grid min-h-[calc(100vh-8rem)] w-full max-w-6xl items-center gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(360px,440px)]">
        <section className="space-y-8">
          <div className="max-w-2xl">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#596053]">
              SentrySearch workspace
            </p>
            <h1 className="mt-4 text-4xl font-semibold leading-tight text-[#171915] sm:text-5xl">
              Enter the intelligence review room.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-[#4f564d]">
              Generate threat reports, inspect source context, and keep saved
              findings organized behind your account boundary.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {trustSignals.map((signal) => (
              <div
                key={signal.label}
                className="border-l border-[#c8c9bd] bg-white/60 px-4 py-3"
              >
                <h2 className="text-sm font-semibold text-[#20231f]">
                  {signal.label}
                </h2>
                <p className="mt-2 text-sm leading-6 text-[#596053]">
                  {signal.description}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section
          aria-labelledby="auth-panel-title"
          className="border border-[#d8d9ce] bg-white p-6 shadow-[0_18px_50px_rgba(23,25,21,0.08)] sm:p-8"
        >
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#6f755f]">
            {eyebrow}
          </p>
          <h2
            id="auth-panel-title"
            className="mt-3 text-2xl font-semibold text-[#171915]"
          >
            {title}
          </h2>
          <p className="mt-3 text-sm leading-6 text-[#5d6458]">
            {description}
          </p>

          <div className="mt-8">{children}</div>

          <div className="mt-6 border-t border-[#e5e5dc] pt-5 text-sm text-[#5d6458]">
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
          className="font-medium text-[#4d5f24] underline-offset-4 hover:underline"
        >
          {actionLabel}
        </Link>
      }
    >
      <div className="border border-[#d9dfca] bg-[#f8fbf2] px-4 py-4 text-sm leading-6 text-[#4a542f]">
        Your workspace will open after the email confirmation link is complete.
      </div>
    </AuthFrame>
  );
}

