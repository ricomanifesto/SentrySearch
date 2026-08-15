import type { ModelRouteProvenance } from '@/lib/api-contracts';

interface RouteProvenanceProps {
  generationRoute?: ModelRouteProvenance | null;
  researchRoute?: ModelRouteProvenance | null;
  synthesisRoute?: ModelRouteProvenance | null;
  evaluationRoute?: ModelRouteProvenance | null;
}

function formatValues(values: string[], unavailable: string) {
  return values.length > 0 ? values.join(', ') : unavailable;
}

export function RouteProvenance({
  generationRoute,
  researchRoute,
  synthesisRoute,
  evaluationRoute,
}: RouteProvenanceProps) {
  const divergentRoutes = [
    researchRoute?.used_fallback
      ? {
          label: 'Evidence research',
          route: researchRoute,
        }
      : null,
    synthesisRoute?.used_fallback
      ? {
          label: 'Report authoring',
          route: synthesisRoute,
        }
      : null,
    evaluationRoute?.used_fallback
      ? {
          label: 'Evaluation',
          route: evaluationRoute,
        }
      : null,
    // TODO(route-provenance-v2): Remove this reader after aggregate-only retained
    // reports expire; do not expand it to new records or pipeline roles.
    !researchRoute && !synthesisRoute && generationRoute?.used_fallback
      ? {
          label: 'All generation calls (legacy aggregate)',
          route: generationRoute,
        }
      : null,
  ].filter((item): item is { label: string; route: ModelRouteProvenance } => item !== null);

  if (divergentRoutes.length === 0) {
    return null;
  }

  return (
    <section
      data-contract="Report.RouteProvenance.v2"
      className="mt-6 rounded-xl border border-amber-200 bg-amber-50 p-5"
    >
      <h2 className="text-base font-semibold text-amber-900">Routing provenance</h2>
      <p className="mt-1 text-sm leading-6 text-amber-700">
        One or more recorded pipeline roles completed through an application-owned fallback route.
      </p>
      <dl className="mt-4 space-y-3">
        {divergentRoutes.map(({ label, route }) => (
          <div key={label}>
            <dt className="text-sm font-medium text-amber-900">{label}</dt>
            <dd className="mt-1 break-words text-sm leading-6 text-amber-700">
              Requested <code>{formatValues(route.requested_models, 'an unrecorded model')}</code>;
              {' '}provider constraint {formatValues(route.requested_providers, 'not pinned')};
              {' '}selected <code>{formatValues(route.selected_models, 'an unrecorded route')}</code>;
              {' '}resolved as <code>{formatValues(route.actual_models, 'an unreported model')}</code>
              {' '}via {formatValues(route.providers, 'an unreported provider')}.
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
