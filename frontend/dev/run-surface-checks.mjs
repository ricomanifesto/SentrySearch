#!/usr/bin/env node

import { spawnSync } from 'node:child_process';

import { routeSurfaces } from './surface-route-contract.mjs';

const uniqueSurfaceScripts = Array.from(new Set(routeSurfaces.map(({ script }) => script)));

function run(command, args) {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

run(process.execPath, ['dev/check-surface-coverage.mjs']);
run(process.execPath, ['dev/check-surface-coverage-regressions.mjs']);

for (const script of uniqueSurfaceScripts) {
  run('npm', ['run', script]);
}
