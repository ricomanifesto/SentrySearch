export type ExportScopeState = {
  recordCount: number;
  packageScope: string;
  queueStatus: string;
  queueDescription: string;
  readinessStatus: string;
  readinessDescription: string;
  actionLabel: string;
  canPrepare: boolean;
};

type ExportScopeInput = {
  loading: boolean;
  failed: boolean;
  matchingCount: number;
  selectedCount: number;
  maxReports?: number;
};

function pluralizedRecords(count: number): string {
  return `${count} record${count === 1 ? '' : 's'}`;
}

export function getExportScopeState({
  loading,
  failed,
  matchingCount,
  selectedCount,
  maxReports,
}: ExportScopeInput): ExportScopeState {
  if (loading) {
    return {
      recordCount: 0,
      packageScope: 'Checking scope',
      queueStatus: 'Checking scope',
      queueDescription: 'Matching report records are still loading.',
      readinessStatus: 'Checking',
      readinessDescription: 'Package readiness will be known after the handoff scope loads.',
      actionLabel: 'Checking package scope…',
      canPrepare: false,
    };
  }
  if (failed) {
    return {
      recordCount: 0,
      packageScope: 'Scope unavailable',
      queueStatus: 'Unavailable',
      queueDescription: 'The matching report count could not be loaded.',
      readinessStatus: 'Not ready',
      readinessDescription: 'Reload the handoff scope before preparing a package.',
      actionLabel: 'Package unavailable',
      canPrepare: false,
    };
  }

  const configuredLimit = Number.isFinite(maxReports)
    ? Math.max(1, Math.trunc(maxReports as number))
    : matchingCount;
  const recordCount = Math.min(
    selectedCount > 0 ? selectedCount : matchingCount,
    configuredLimit,
  );

  if (recordCount === 0) {
    return {
      recordCount: 0,
      packageScope: '0 records',
      queueStatus: '0 records',
      queueDescription: 'No report records match the current handoff constraints.',
      readinessStatus: 'Nothing ready',
      readinessDescription: 'A package can be prepared after at least one report matches.',
      actionLabel: 'No package to prepare',
      canPrepare: false,
    };
  }

  const scope = selectedCount > 0
    ? `${pluralizedRecords(recordCount)} selected`
    : `${pluralizedRecords(recordCount)} matching`;
  return {
    recordCount,
    packageScope: scope,
    queueStatus: scope,
    queueDescription: selectedCount > 0
      ? 'Only selected report records will be packaged.'
      : 'Every matching report record within the configured cap will be packaged.',
    readinessStatus: 'Ready',
    readinessDescription: `${pluralizedRecords(recordCount)} will be included when generated.`,
    actionLabel: 'Prepare package',
    canPrepare: true,
  };
}
