import assert from 'node:assert/strict';
import test from 'node:test';

import { getGenerationErrorMessage } from '../src/lib/generation-errors';

test('blames target input only for a validation response', () => {
  const message = getGenerationErrorMessage({ isAxiosError: true, response: { status: 422 } });
  assert.match(message, /Check the target name/);
});

test('explains timeout and service failures without blaming the analyst', () => {
  const timeout = getGenerationErrorMessage({ isAxiosError: true, code: 'ECONNABORTED' });
  const service = getGenerationErrorMessage({ isAxiosError: true, response: { status: 503 } });

  assert.match(timeout, /first run can take longer/i);
  assert.match(service, /waking/i);
  assert.doesNotMatch(timeout, /Check the target name/);
  assert.doesNotMatch(service, /Check the target name/);
});

test('distinguishes an unreachable service from an unknown failure', () => {
  const unreachable = getGenerationErrorMessage({ isAxiosError: true, request: {} });
  const unknown = getGenerationErrorMessage(new Error('unexpected'));

  assert.match(unreachable, /could not reach the research service/i);
  assert.match(unknown, /could not be started/i);
});
