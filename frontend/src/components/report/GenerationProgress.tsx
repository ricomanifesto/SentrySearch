import type { GenerationStage } from '@/lib/api-contracts';

type GenerationProgressProps = {
  toolName: string;
  stage: GenerationStage;
  elapsedSeconds: number;
};

const visibleStages: Array<{ stage: GenerationStage; label: string; detail: string }> = [
  { stage: 'queued', label: 'Preparing research', detail: 'Opening a protected background run.' },
  { stage: 'researching', label: 'Researching sources', detail: 'Gathering evidence across independent research areas.' },
  { stage: 'synthesizing', label: 'Synthesizing narrative', detail: 'Turning attested evidence into a structured profile.' },
  { stage: 'validating', label: 'Validating report sections', detail: 'Checking source, structure, and quality requirements.' },
  { stage: 'finalizing', label: 'Saving review record', detail: 'Persisting the narrative and source evidence.' },
];

function formatElapsed(seconds: number) {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(safeSeconds / 60);
  const remainder = safeSeconds % 60;
  return `${minutes}m ${String(remainder).padStart(2, '0')}s`;
}

export function GenerationProgress({ toolName, stage, elapsedSeconds }: GenerationProgressProps) {
  const stageIndex = Math.max(0, visibleStages.findIndex((item) => item.stage === stage));
  const currentStage = visibleStages[stageIndex];

  return (
    <section
      data-contract="Report.GenerationProgress.v1"
      className="mt-8 rounded-xl border border-zinc-200 bg-white px-6 py-8"
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-sm font-medium text-blue-700">Generating {toolName}</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-zinc-950">
            {currentStage.label}
          </h1>
          <p className="mt-2 max-w-xl text-sm leading-6 text-zinc-600">{currentStage.detail}</p>
        </div>
        <span className="shrink-0 rounded-md bg-zinc-100 px-3 py-1.5 font-mono text-sm text-zinc-700">
          {formatElapsed(elapsedSeconds)} elapsed
        </span>
      </div>

      <ol className="mt-7 grid gap-3 sm:grid-cols-5">
        {visibleStages.map((item, index) => {
          const state = index < stageIndex ? 'Complete' : index === stageIndex ? 'In progress' : 'Waiting';
          return (
            <li key={item.stage} className="border-t-2 border-zinc-200 pt-3 data-[active=true]:border-blue-600" data-active={index <= stageIndex}>
              <p className="text-sm font-medium text-zinc-950">{item.label}</p>
              <p className="mt-1 text-sm text-zinc-500">{state}</p>
            </li>
          );
        })}
      </ol>

      <p className="mt-6 border-t border-zinc-200 pt-4 text-sm leading-6 text-zinc-500">
        Research and synthesis can take a few minutes. The first run can take longer while the service wakes; this page updates on its own.
      </p>
    </section>
  );
}
