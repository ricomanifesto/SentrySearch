// @ts-expect-error node:test has no types in this package.
import { test } from "node:test";
// @ts-expect-error node:assert has no types in this package.
import assert from "node:assert/strict";
import { MAX_ROWS, parseReceipt, ReceiptRejected, ReceiptStore, type Receipt } from "../src/shared/receipts";
import { memorySql } from "./sqlite";

const RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d21";
const BOOT = "a".repeat(32);

function receipt(sequence: number, overrides: Partial<Receipt> = {}): Receipt {
  return {
    kind: "sentry.worker-readiness.v1",
    release_id: RELEASE,
    boot_id: BOOT,
    sequence,
    observed_at: "2026-10-09T01:00:00.000000Z",
    uptime_seconds: 1.5,
    alive: true,
    ready: true,
    draining: false,
    phase: "idle",
    phase_elapsed_seconds: 0.1,
    phase_budget_seconds: 0,
    error_code: null,
    ...overrides,
  };
}

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

test("only the worker's v1 receipt for this release parses", () => {
  assert.deepEqual(parseReceipt(bytes(receipt(1)), RELEASE), receipt(1));
  const bad: unknown[] = [
    { ...receipt(1), extra: 1 },
    { ...receipt(1), release_id: "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d22" },
    { ...receipt(1), kind: "other" },
    { ...receipt(0) },
    { ...receipt(1), sequence: 1.5 },
    { ...receipt(1), boot_id: "z".repeat(32) },
    { ...receipt(1), phase: "hacked" },
    { ...receipt(1), ready: "yes" },
    { ...receipt(1), error_code: "Drop Table" },
    { ...receipt(1), uptime_seconds: -1 },
    [receipt(1)],
  ];
  for (const value of bad) assert.throws(() => parseReceipt(bytes(value), RELEASE), ReceiptRejected);
  assert.throws(() => parseReceipt(new TextEncoder().encode("{" + " ".repeat(3000) + "}"), RELEASE), ReceiptRejected);
  assert.throws(() => parseReceipt(new Uint8Array([0xff, 0xfe]), RELEASE), ReceiptRejected);
});

test("complete history, gaps, conflicting duplicates and starts are kept apart", () => {
  const store = new ReceiptStore(memorySql());
  store.record("start-a", receipt(1));
  store.record("start-a", receipt(2));
  store.record("start-a", receipt(2)); // identical redelivery
  assert.equal(store.view("start-a").complete, true);
  store.record("start-a", receipt(4));
  assert.deepEqual(store.view("start-a").gaps, { [BOOT]: [3] });
  assert.equal(store.view("start-a").complete, false);
  store.record("start-a", receipt(3));
  store.record("start-a", receipt(3, { ready: false }));
  const view = store.view("start-a");
  assert.equal(view.duplicatesConflicting, 1);
  assert.equal(view.complete, false);
  assert.equal(store.view("start-b").complete, false);
  assert.equal(store.view("start-b").receipts.length, 0);
});

test("eviction keeps a watermark so evicted history is never reported complete", () => {
  const store = new ReceiptStore(memorySql());
  for (let sequence = 1; sequence <= MAX_ROWS + 10; sequence++) store.record("start-a", receipt(sequence));
  const view = store.view("start-a");
  assert.equal(view.receipts.length, MAX_ROWS);
  assert.equal(view.evictedThrough[BOOT], 10);
  assert.deepEqual(view.gaps, {});
  assert.equal(view.complete, false);
  store.record("start-a", receipt(5)); // already evicted: not resurrected
  assert.equal(store.view("start-a").receipts.length, MAX_ROWS);
});
