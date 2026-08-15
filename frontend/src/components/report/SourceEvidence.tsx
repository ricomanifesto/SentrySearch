import type {
  ClaimAttributionStatus,
  EvidenceAdmissibility,
  ReportSource,
} from '@/lib/api-contracts';

import { getSafeExternalUrl } from './report-links';

type SourceEvidenceProps = {
  sources: ReportSource[];
  heading?: string;
  dateLabel?: 'Accessed' | 'Captured';
  attributionStatus?: ClaimAttributionStatus;
  attributionVersion?: string | null;
  evidenceAdmissibility?: EvidenceAdmissibility | null;
};

export function SourceEvidence({
  sources,
  heading = 'Source evidence',
  dateLabel = 'Accessed',
  attributionStatus,
  attributionVersion,
  evidenceAdmissibility,
}: SourceEvidenceProps) {
  const nonOperationalSources = evidenceAdmissibility?.source_observations.filter(
    (source) => source.purpose !== 'operational',
  ) ?? [];
  const contextIndicators = evidenceAdmissibility?.indicator_observations.filter(
    (indicator) => indicator.disposition === 'context_required',
  ) ?? [];
  const blockingFindings = evidenceAdmissibility?.blocking_findings ?? [];
  return (
    <section data-contract="Report.SourceEvidence.v1" aria-labelledby="source-evidence-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="source-evidence-heading" className="text-base font-semibold text-zinc-950">
          {heading}
        </h2>
        <span className="text-sm text-zinc-500">
          {sources.length} operational {sources.length === 1 ? 'source' : 'sources'}
        </span>
      </div>

      {attributionStatus === 'attributed' ? (
        <p className="mt-2 text-sm leading-6 text-emerald-700">
          {attributionVersion === '4'
            ? evidenceAdmissibility?.status === 'passed'
              ? 'Every stored high-risk field item is covered by admissible attribution schema 4.'
              : 'Attribution schema 4 records an evidence role for every stored high-risk field item; admissibility is reported separately below.'
            : `Selected high-risk claims link to this source ledger through legacy attribution schema ${attributionVersion ?? '2'}.`}
        </p>
      ) : attributionStatus === 'unattributed' ? (
        <p className="mt-2 text-sm leading-6 text-amber-700">
          The generated claim-level attribution did not pass the current contract.
        </p>
      ) : attributionStatus === 'legacy' ? (
        <p className="mt-2 text-sm leading-6 text-zinc-500">
          Claim-level attribution was not recorded for this legacy report.
        </p>
      ) : null}

      {evidenceAdmissibility?.status === 'passed' ? (
        <p className="mt-2 text-sm leading-6 text-emerald-700">
          Operational evidence checks passed under admissibility schema {evidenceAdmissibility.schema_version}.
        </p>
      ) : evidenceAdmissibility?.status === 'blocked' ? (
        <p className="mt-2 text-sm leading-6 text-red-700">
          Operational evidence checks blocked this record from reuse.
        </p>
      ) : (
        <p className="mt-2 text-sm leading-6 text-amber-700">
          {blockingFindings.length > 0
            ? 'Operational safety could not be assessed because high-risk evidence coverage was incomplete.'
            : 'Operational evidence admissibility was not assessed for this retained record.'}
        </p>
      )}

      {blockingFindings.length > 0 ? (
        <div
          data-contract="Report.EvidenceBlockingFindings.v1"
          className={`mt-4 rounded-lg border p-4 ${
            evidenceAdmissibility?.status === 'blocked'
              ? 'border-red-200 bg-red-50'
              : 'border-amber-200 bg-amber-50'
          }`}
        >
          <h3 className="text-sm font-semibold text-zinc-950">
            {evidenceAdmissibility?.status === 'blocked'
              ? 'Why this record was blocked'
              : 'Why this run could not finalize'}
          </h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm leading-6 text-zinc-800">
            {blockingFindings.map((finding, index) => (
              <li key={`${index}-${finding}`}>{finding}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {sources.length > 0 ? (
        <ol className="mt-4 space-y-4">
          {sources.map((source, index) => {
            const safeUrl = getSafeExternalUrl(source.url);
            return (
              <li
                id={source.source_id ? `source-${source.source_id}` : undefined}
                key={`${source.url}-${index}`}
                className="scroll-mt-24 border-t border-zinc-100 pt-4 first:border-t-0 first:pt-0"
              >
                <div className="flex items-start gap-3">
                  <span className="pt-0.5 font-mono text-sm text-zinc-400">
                    {source.source_id ?? String(index + 1).padStart(2, '0')}
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
          No source passed into this record&apos;s operational evidence ledger.
        </p>
      )}

      {nonOperationalSources.length > 0 ? (
        <div className="mt-6 border-t border-zinc-200 pt-5">
          <h3 className="text-sm font-semibold text-zinc-950">
            Not used as operational evidence
          </h3>
          <p className="mt-1 text-sm leading-6 text-zinc-500">
            These sources remain named in the audit record even though their purpose prevents operational reuse.
          </p>
          <ol className="mt-3 space-y-3">
            {nonOperationalSources.map((source) => {
              const safeUrl = getSafeExternalUrl(source.url);
              return (
                <li id={source.source_id ? `source-${source.source_id}` : undefined} key={`${source.source_id ?? source.url}-${source.rule_id}`} className="scroll-mt-24 rounded-lg border border-amber-200 bg-amber-50 p-3">
                  <p className="text-sm font-medium text-zinc-950">
                    {safeUrl ? (
                      <a href={safeUrl} target="_blank" rel="noopener noreferrer" className="text-blue-700 underline underline-offset-2">
                        {source.title}
                      </a>
                    ) : source.title}
                  </p>
                  <p className="mt-1 text-sm leading-6 text-amber-900">
                    {source.purpose === 'context_only' ? 'Context only' : 'Excluded'} · {source.reason}
                  </p>
                </li>
              );
            })}
          </ol>
        </div>
      ) : null}

      {contextIndicators.length > 0 ? (
        <div className="mt-6 border-t border-zinc-200 pt-5">
          <h3 className="text-sm font-semibold text-zinc-950">Environment context required</h3>
          <ul className="mt-2 space-y-2 text-sm leading-6 text-amber-900">
            {contextIndicators.map((indicator) => (
              <li key={`${indicator.claim_field}-${indicator.claim_index}`}>
                <span className="font-mono">{indicator.value}</span> · {indicator.reason}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
