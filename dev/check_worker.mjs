import assert from 'node:assert/strict';

import worker from '../worker.js';

const baseUrl = 'https://worker.example.test';
const env = {
  SENTRY_KV: {
    async get() {
      return null;
    },
  },
};

async function request(path, init = {}) {
  return worker.fetch(new Request(`${baseUrl}${path}`, init), env);
}

const health = await request('/health');
assert.equal(health.status, 200);
assert.equal((await health.json()).status, 'degraded');
assert.equal(health.headers.get('access-control-allow-origin'), '*');

const removedDebugRoute = await request('/debug-pinecone');
assert.equal(removedDebugRoute.status, 404);

const invalidSearch = await request('/hybrid-search', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ queries: [] }),
});
assert.equal(invalidSearch.status, 400);

const keywordSearch = await request('/keyword-search', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ query: 'credential access', maxResults: 1000 }),
});
assert.equal(keywordSearch.status, 200);
assert.deepEqual(await keywordSearch.json(), { results: [] });

const preflight = await request('/hybrid-search', { method: 'OPTIONS' });
assert.equal(preflight.status, 204);
assert.equal(preflight.headers.get('access-control-allow-methods'), 'GET, POST, OPTIONS');

console.log('Worker contract checks passed');
