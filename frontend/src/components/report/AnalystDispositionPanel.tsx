'use client';

import React from 'react';

import type {
  AnalystDispositionEvent,
  ReportDetail,
  StoredAnalystDisposition,
} from '@/lib/api-contracts';
import {
  getAnalystDispositionClasses,
  getAnalystDispositionLabel,
} from '@/lib/analyst-disposition';
import { getRecordedConflictCount } from '@/lib/review-attention';
import { formatDate } from '@/lib/utils';

type AnalystDispositionPanelProps = {
  report: ReportDetail;
  disabled?: boolean;
  pending?: boolean;
  failed?: boolean;
  reevaluationPending?: boolean;
  onRecord: (disposition: StoredAnalystDisposition, note: string) => void;
  onReevaluate: () => void;
};

const choices: Array<{
  value: StoredAnalystDisposition;
  label: string;
  description: string;
}> = [
  {
    value: 'accepted',
    label: 'Accept for reuse',
    description: 'The current evaluation and evidence are suitable for analyst handoff.',
  },
  {
    value: 'needs_revision',
    label: 'Needs revision',
    description: 'Keep this record in unresolved work until the named gaps are addressed.',
  },
  {
    value: 'rejected',
    label: 'Reject',
    description: 'Do not use this evaluation vintage for operational decisions.',
  },
];

function dispositionEventLabel(event: AnalystDispositionEvent): string {
  return `${getAnalystDispositionLabel(event.disposition)} · evaluation ${event.evaluation_attempt}`;
}

export function AnalystDispositionPanel({
  report,
  disabled = false,
  pending = false,
  failed = false,
  reevaluationPending = false,
  onRecord,
  onReevaluate,
}: AnalystDispositionPanelProps) {
  const currentSelection = report.current_disposition?.disposition ?? '';
  const [selected, setSelected] = React.useState<StoredAnalystDisposition | ''>(currentSelection);
  const [note, setNote] = React.useState('');
  const conflictCount = getRecordedConflictCount(report.quality_assessment);
  const acceptanceBlocked = !report.eligible_for_acceptance;
  const conflictNoteRequired = selected === 'accepted' && conflictCount > 0;
  const missingRequiredNote = conflictNoteRequired && note.trim().length === 0;

  if (!report.eligible_for_judgment) return null;

  return (
    <section
      data-contract="Report.AnalystDisposition.v1"
      className="mt-8 border-t border-zinc-200 pt-6"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-zinc-950">Analyst disposition</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-zinc-600">
            Record whether this evaluation vintage can be reused. Each judgment is appended to the audit history; earlier decisions are never overwritten.
          </p>
        </div>
        <span className={`shrink-0 rounded-md px-2 py-1 text-sm font-medium ${getAnalystDispositionClasses(report.analyst_disposition)}`}>
          {getAnalystDispositionLabel(report.analyst_disposition)}
        </span>
      </div>

      <fieldset className="mt-5 divide-y divide-zinc-200 border-y border-zinc-200" disabled={disabled || pending}>
        <legend className="sr-only">Disposition for evaluation {report.evaluation_attempts}</legend>
        {choices.map((choice) => (
          <label
            key={choice.value}
            className={`block border-l-4 py-4 pl-4 pr-3 ${choice.value === 'accepted' && acceptanceBlocked ? 'cursor-not-allowed border-transparent bg-zinc-50 opacity-60' : 'cursor-pointer'} ${selected === choice.value ? 'border-blue-600 bg-blue-50' : 'border-transparent'}`}
          >
            <span className="flex items-start gap-3">
              <input
                type="radio"
                name="analyst_disposition"
                value={choice.value}
                checked={selected === choice.value}
                onChange={() => setSelected(choice.value)}
                disabled={choice.value === 'accepted' && acceptanceBlocked}
                className="mt-1 h-4 w-4 border-zinc-300 text-blue-600 focus:ring-blue-500"
              />
              <span>
                <span className="block text-sm font-medium text-zinc-950">{choice.label}</span>
                <span className="mt-1 block text-sm leading-6 text-zinc-600">{choice.description}</span>
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      <label className="mt-4 block">
        <span className="text-sm font-medium text-zinc-800">
          Reviewer note{' '}
          <span className="font-normal text-zinc-500">
            {conflictNoteRequired ? `(required to accept ${conflictCount} recorded conflict${conflictCount === 1 ? '' : 's'})` : '(optional)'}
          </span>
        </span>
        <textarea
          value={note}
          onChange={(event) => setNote(event.target.value)}
          maxLength={1000}
          aria-required={conflictNoteRequired}
          disabled={disabled || pending}
          rows={3}
          placeholder="Name the evidence checked, remaining uncertainty, or required revision."
          className="mt-2 block w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-950 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 disabled:bg-zinc-50"
        />
      </label>

      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
        <button
          type="button"
          disabled={disabled || pending || !selected || missingRequiredNote || (selected === 'accepted' && acceptanceBlocked)}
          onClick={() => {
            if (selected && !missingRequiredNote) onRecord(selected, note);
          }}
          className="inline-flex h-10 items-center justify-center rounded-lg bg-zinc-950 px-4 text-sm font-medium text-white hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
        >
          {pending ? 'Recording judgment…' : 'Record judgment'}
        </button>
        {report.current_disposition ? (
          <button
            type="button"
            disabled={disabled || reevaluationPending}
            onClick={onReevaluate}
            className="inline-flex h-10 items-center justify-center rounded-lg border border-zinc-300 bg-white px-4 text-sm font-medium text-zinc-800 hover:bg-zinc-50 disabled:pointer-events-none disabled:opacity-50"
          >
            {reevaluationPending ? 'Starting re-evaluation…' : 'Re-run evaluation'}
          </button>
        ) : null}
        <p className="text-sm text-zinc-500">Applies to evaluation {report.evaluation_attempts}.</p>
      </div>
      {failed ? (
        <p className="mt-3 text-sm text-red-700" role="alert">
          The judgment was not recorded. The existing audit history is unchanged.
        </p>
      ) : null}
      {conflictNoteRequired ? (
        <p className="mt-3 text-sm text-amber-800">
          Name why reuse is justified while the recorded conflicts remain unresolved.
        </p>
      ) : null}
      {acceptanceBlocked ? (
        <p className="mt-3 text-sm text-amber-800">
          Accept for reuse is unavailable until deterministic evidence admissibility passes. Needs revision and Reject remain available for this audit record.
        </p>
      ) : null}

      {report.disposition_history.length > 0 ? (
        <details className="mt-5 border-t border-zinc-200 pt-4">
          <summary className="cursor-pointer text-sm font-medium text-zinc-950 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
            Judgment history · {report.disposition_history.length}
          </summary>
          <ol className="mt-3 divide-y divide-zinc-200 border-y border-zinc-200">
            {[...report.disposition_history].reverse().map((event) => (
              <li key={event.id} className="py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className={`rounded-md px-2 py-0.5 text-sm font-medium ${getAnalystDispositionClasses(event.disposition)}`}>
                    {dispositionEventLabel(event)}
                  </span>
                  <span className="text-sm text-zinc-500">{formatDate(event.created_at)}{event.is_current ? ' · current vintage' : ' · historical'}</span>
                </div>
                {event.note ? <p className="mt-2 text-sm leading-6 text-zinc-700">{event.note}</p> : null}
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </section>
  );
}
