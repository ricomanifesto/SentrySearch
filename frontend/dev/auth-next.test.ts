import assert from 'node:assert/strict';
import test from 'node:test';

import { getSafeNextPath } from '../src/lib/auth-next';

test('preserves an internal report deep link and its query', () => {
  assert.equal(
    getSafeNextPath('/reports/4c85?include_content=true'),
    '/reports/4c85?include_content=true',
  );
});

test('rejects external and protocol-relative redirect targets', () => {
  assert.equal(getSafeNextPath('https://example.com/phish'), '/dashboard');
  assert.equal(getSafeNextPath('//example.com/phish'), '/dashboard');
  assert.equal(getSafeNextPath('/\\example.com/phish'), '/dashboard');
});

test('uses the dashboard when no protected intent exists', () => {
  assert.equal(getSafeNextPath(null), '/dashboard');
  assert.equal(getSafeNextPath(''), '/dashboard');
});
