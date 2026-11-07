import type { RoutePerformance } from './api-contracts';

export interface RouteQualityPresentation {
  /** Average with its 95% half-width, or the unscored label. */
  summary: string;
  /** Present when another scored route sits inside this route's 95% interval. */
  indistinguishableNote: string | null;
}

/**
 * Present a route's mean content quality with its sample-size uncertainty so
 * the comparison does not imply a ranking the scored sample cannot support.
 */
export function getRouteQualityPresentation(
  route: RoutePerformance,
  routes: RoutePerformance[],
  routeLabels: Record<RoutePerformance['route'], string>,
): RouteQualityPresentation {
  if (route.avg_quality_score == null) {
    return { summary: 'Content quality not scored', indistinguishableNote: null };
  }

  const average = route.avg_quality_score.toFixed(2);
  const summary = route.quality_half_width == null
    ? `${average} average content quality`
    : `${average} ± ${route.quality_half_width.toFixed(2)} average content quality`;

  const overlapping = routes.filter((other) => (
    other.route !== route.route
    && other.avg_quality_score != null
    && !route.distinguishable_from.includes(other.route)
  ));

  return {
    summary,
    indistinguishableNote: overlapping.length === 0
      ? null
      : `Not distinguishable from ${overlapping.map((other) => routeLabels[other.route].toLowerCase()).join(', ')} at 95% confidence`,
  };
}
