import type { GenerationErrorCode } from './api-contracts';

export type GenerationFailurePresentation = {
  heading: string;
  detail: string;
  retryLabel: string;
  targetExonerated: boolean;
};

export function getGenerationFailurePresentation(
  code: GenerationErrorCode | null | undefined,
  retryable: boolean | null | undefined,
): GenerationFailurePresentation {
  switch (code) {
    case 'provider_rate_limited':
      return {
        heading: 'The model route reached its request limit',
        detail: 'Your target was not the cause. The recorded provider routes could not accept this run.',
        retryLabel: 'Retry this target',
        targetExonerated: true,
      };
    case 'provider_unavailable':
    case 'provider_timeout':
      return {
        heading: code === 'provider_timeout' ? 'The model route timed out' : 'The model route was unavailable',
        detail: 'Your target was not the cause. Every recorded model route stopped before usable output arrived.',
        retryLabel: 'Retry this target',
        targetExonerated: true,
      };
    case 'model_output_invalid':
      return {
        heading: 'The generated output did not pass its contract',
        detail: 'The model responded, but the structured report could not be validated. No unvalidated report was saved.',
        retryLabel: 'Retry this target',
        targetExonerated: true,
      };
    case 'model_request_rejected':
      return {
        heading: 'The authoring route rejected the report contract',
        detail: 'Your target was not the cause. The model route stopped before it produced report content.',
        retryLabel: 'Retry this target',
        targetExonerated: true,
      };
    case 'evidence_unavailable':
      return {
        heading: 'Not enough attested evidence was returned',
        detail: 'This target may be too obscure or may need a more specific name or known alias before a defensible report can be built.',
        retryLabel: 'Revise the target',
        targetExonerated: false,
      };
    case 'evidence_unattested':
      return {
        heading: 'The evidence contract did not hold',
        detail: 'The run produced claims or sources that could not be reconciled with the attested evidence, so the report was not finalized.',
        retryLabel: 'Start another run',
        targetExonerated: false,
      };
    case 'evidence_inadmissible':
      return {
        heading: 'The evidence was unsafe for operational use',
        detail: 'The run found documentation, special-use, training, or otherwise non-operational evidence in a high-risk claim. No unsafe report was finalized.',
        retryLabel: 'Start another run',
        targetExonerated: false,
      };
    case 'persistence_failed':
      return {
        heading: 'The review record could not be saved',
        detail: 'Analysis reached the save step, but the report record did not commit. The failure is retryable.',
        retryLabel: 'Retry this target',
        targetExonerated: true,
      };
    default:
      return {
        heading: 'The run stopped unexpectedly',
        detail: retryable
          ? 'The saved failure record marks this run as retryable, but it does not identify a more specific cause.'
          : 'The saved failure record does not identify a safe cause or a reliable retry path.',
        retryLabel: retryable ? 'Retry this target' : 'Review the target',
        targetExonerated: false,
      };
  }
}
