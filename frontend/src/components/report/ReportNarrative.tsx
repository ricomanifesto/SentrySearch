import type { ComponentPropsWithoutRef, ReactNode } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { getSafeExternalUrl } from './report-links';
import { reportHeadingId } from '@/lib/report-content';
import { applyClaimAttributions } from '@/lib/claim-attribution';
import type { ClaimAttributionEntry } from '@/lib/api-contracts';

type ReportNarrativeProps = {
  markdown: string;
  claimAttributions?: ClaimAttributionEntry[];
};

function safeNarrativeUrl(value: string | undefined): string | null {
  if (value && /^#source-S[1-9]\d*$/.test(value)) return value;
  return getSafeExternalUrl(value);
}

export function ReportNarrative({ markdown, claimAttributions }: ReportNarrativeProps) {
  const attributedMarkdown = applyClaimAttributions(markdown, claimAttributions);
  const headingText = (children: ReactNode): string => (
    Array.isArray(children) ? children.join('') : String(children ?? '')
  );
  return (
    <div data-contract="Report.RenderedNarrative.v1" className="report-narrative mt-5 min-w-0 text-zinc-700">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        urlTransform={(url) => safeNarrativeUrl(url) ?? ''}
        components={{
          h1: ({ children }) => (
            <h2 className="mt-10 border-b border-zinc-200 pb-3 text-2xl font-semibold tracking-tight text-zinc-950 first:mt-0">
              {children}
            </h2>
          ),
          h2: ({ children }) => {
            const label = headingText(children);
            return (
              <h3 id={reportHeadingId(label)} className="scroll-mt-24 mt-10 border-b border-zinc-200 pb-2 text-xl font-semibold tracking-tight text-zinc-950 first:mt-0">
                {children}
              </h3>
            );
          },
          h3: ({ children }) => (
            <h4 className="mt-8 text-lg font-semibold text-zinc-950">{children}</h4>
          ),
          h4: ({ children }) => (
            <h5 className="mt-6 text-base font-semibold text-zinc-950">{children}</h5>
          ),
          p: ({ children }) => <p className="mt-4 text-base leading-7 first:mt-0">{children}</p>,
          a: ({ href, children }) => {
            const safeHref = safeNarrativeUrl(href);
            const isSourceLink = safeHref?.startsWith('#source-') ?? false;
            return safeHref ? (
              <a
                href={safeHref}
                target={isSourceLink ? undefined : '_blank'}
                rel={isSourceLink ? undefined : 'noopener noreferrer'}
                className={isSourceLink
                  ? 'ml-1 inline-flex rounded bg-blue-50 px-1.5 py-0.5 font-mono text-xs font-semibold text-blue-700 no-underline hover:bg-blue-100'
                  : 'font-medium text-blue-700 underline decoration-blue-300 underline-offset-2 hover:text-blue-800'}
              >
                {children}
              </a>
            ) : (
              <span>{children}</span>
            );
          },
          ul: ({ children }) => <ul className="mt-4 list-disc space-y-2 pl-6 leading-7">{children}</ul>,
          ol: ({ children }) => <ol className="mt-4 list-decimal space-y-2 pl-6 leading-7">{children}</ol>,
          li: ({ children }) => <li className="pl-1">{children}</li>,
          blockquote: ({ children }) => (
            <blockquote className="mt-5 border-l-4 border-blue-200 bg-blue-50 px-4 py-3 text-zinc-700">
              {children}
            </blockquote>
          ),
          table: ({ children }) => (
            <div className="mt-5 overflow-x-auto rounded-lg border border-zinc-200">
              <table className="w-full border-collapse text-left text-sm">{children}</table>
            </div>
          ),
          thead: ({ children }) => <thead className="bg-zinc-100 text-zinc-950">{children}</thead>,
          th: ({ children }) => <th className="border-b border-zinc-200 px-3 py-2 font-semibold">{children}</th>,
          td: ({ children }) => <td className="border-b border-zinc-100 px-3 py-2 align-top leading-6 last:border-b-0">{children}</td>,
          pre: ({ children }) => (
            <pre className="mt-5 overflow-x-auto rounded-lg border border-zinc-200 bg-[var(--surface-0)] p-4 font-mono text-sm leading-6 text-zinc-800">
              {children}
            </pre>
          ),
          code: ({ className, children, ...props }: ComponentPropsWithoutRef<'code'>) => (
            <code
              className={className ?? 'rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-sm text-zinc-900'}
              {...props}
            >
              {children}
            </code>
          ),
          hr: () => <hr className="my-8 border-zinc-200" />,
          strong: ({ children }) => <strong className="font-semibold text-zinc-950">{children}</strong>,
        }}
      >
        {attributedMarkdown}
      </ReactMarkdown>
    </div>
  );
}
