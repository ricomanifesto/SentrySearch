import type { ReportSource } from '@/lib/api-contracts';

import { getSafeExternalUrl } from './report-links';

type SourceEvidenceProps = {
  sources: ReportSource[];
  heading?: string;
  dateLabel?: 'Accessed' | 'Captured';
};

export function SourceEvidence({
  sources,
  heading = 'Source evidence',
  dateLabel = 'Accessed',
}: SourceEvidenceProps) {
  return (
    <section data-contract="Report.SourceEvidence.v1" aria-labelledby="source-evidence-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="source-evidence-heading" className="text-base font-semibold text-zinc-950">
          {heading}
        </h2>
        <span className="text-sm text-zinc-500">
          {sources.length} {sources.length === 1 ? 'source' : 'sources'}
        </span>
      </div>

      {sources.length > 0 ? (
        <ol className="mt-4 space-y-4">
          {sources.map((source, index) => {
            const safeUrl = getSafeExternalUrl(source.url);
            return (
              <li key={`${source.url}-${index}`} className="border-t border-zinc-100 pt-4 first:border-t-0 first:pt-0">
                <div className="flex items-start gap-3">
                  <span className="pt-0.5 font-mono text-sm text-zinc-400">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <div className="min-w-0 flex-1">
                    {safeUrl ? (
                      <a
                        href={safeUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-medium leading-6 text-blue-700 underline decoration-blue-300 underline-offset-2 hover:text-blue-800"
                      >
                        {source.title}
                      </a>
                    ) : (
                      <p className="font-medium leading-6 text-zinc-950">{source.title}</p>
                    )}
                    <p className="mt-1 break-words font-mono text-sm text-zinc-500">{source.domain}</p>
                    <p className="mt-2 text-sm leading-6 text-zinc-600">{source.key_findings}</p>
                    <p className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-sm text-zinc-500">
                      <span>{source.content_type}</span>
                      <span>Relevance {source.relevance_score}</span>
                      <span>{dateLabel} {source.access_date}</span>
                    </p>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="mt-3 text-sm leading-6 text-amber-700">
          No structured source evidence is attached to this record.
        </p>
      )}
    </section>
  );
}
