// @ts-expect-error node:test has no types in this package.
import { test } from "node:test";
// @ts-expect-error node:assert has no types in this package.
import assert from "node:assert/strict";
import { MAX_BOOTS, MAX_ROWS, parseReceipt, ReceiptRejected, ReceiptStore, type Receipt } from "../src/shared/receipts";
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
  assert.equal(store.view("start-a", false).complete, true);
  store.record("start-a", receipt(4));
  assert.deepEqual(store.view("start-a", false).gaps, { [BOOT]: [3] });
  assert.equal(store.view("start-a", false).complete, false);
  store.record("start-a", receipt(3));
  store.record("start-a", receipt(3, { ready: false }));
  const view = store.view("start-a", false);
  assert.equal(view.duplicatesConflicting, 1);
  assert.equal(view.complete, false);
  assert.equal(store.view("start-b", false).complete, false);
  assert.equal(store.view("start-b", false).receipts.length, 0);
});

test("eviction keeps a watermark so evicted history is never reported complete", () => {
  const store = new ReceiptStore(memorySql());
  for (let sequence = 1; sequence <= MAX_ROWS + 10; sequence++) store.record("start-a", receipt(sequence));
  const view = store.view("start-a", false);
  assert.equal(view.receipts.length, MAX_ROWS);
  assert.equal(view.evictedThrough[BOOT], 10);
  assert.deepEqual(view.gaps, {});
  assert.equal(view.complete, false);
  store.record("start-a", receipt(5)); // already evicted: not resurrected
  assert.equal(store.view("start-a", false).receipts.length, MAX_ROWS);
});

test("an ended start is complete only when every boot closed with its terminal receipt", () => {
  const store = new ReceiptStore(memorySql());
  store.record("start-a", receipt(1));
  store.record("start-a", receipt(2));
  assert.equal(store.view("start-a", false).complete, true);
  // The container died before its final receipts: nothing shows as a gap.
  const cut = store.view("start-a", true);
  assert.deepEqual(cut.gaps, {});
  assert.deepEqual(cut.unterminated, [BOOT]);
  assert.equal(cut.complete, false);
  // "stopped" while still alive is not the end: the terminal receipt may be lost.
  store.record("start-a", receipt(3, { phase: "stopped", ready: false, draining: true }));
  assert.deepEqual(store.view("start-a", true).unterminated, [BOOT]);
  assert.equal(store.view("start-a", true).complete, false);
  store.record("start-a", receipt(4, { phase: "stopped", alive: false, ready: false, draining: true, error_code: "worker_exited" }));
  assert.equal(store.view("start-a", true).complete, true);
});

test("boot ids per start are bounded and a refusal is never complete", () => {
  const sql = memorySql();
  const store = new ReceiptStore(sql);
  for (let boot = 0; boot < MAX_BOOTS; boot++) store.record("start-a", receipt(1, { boot_id: boot.toString(16).padStart(32, "0") }));
  assert.equal(store.view("start-a", false).complete, true);
  for (let boot = MAX_BOOTS; boot < 2000; boot++) {
    assert.throws(() => store.record("start-a", receipt(1, { boot_id: boot.toString(16).padStart(32, "0") })), ReceiptRejected);
  }
  const view = store.view("start-a", false);
  assert.equal(view.refusedBoots, 2000 - MAX_BOOTS);
  assert.equal(view.complete, false);
  assert.equal(Number(sql.exec("SELECT COUNT(*) AS n FROM receipt_meta").toArray()[0]?.n), MAX_BOOTS);
  store.forget("start-a");
  for (const table of ["receipts", "receipt_meta", "receipt_starts"]) {
    assert.equal(Number(sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).toArray()[0]?.n), 0, table);
  }
});

test("pages follow the received order from a cursor and say when history after it is gone", () => {
  const store = new ReceiptStore(memorySql());
  for (let sequence = 1; sequence <= 5; sequence++) store.record("start-a", receipt(sequence));
  store.record("start-b", receipt(1, { boot_id: "b".repeat(32) }));
  const first = store.page("start-a", 0, 2, false);
  assert.deepEqual(first.receipts.map((r) => r.sequence), [1, 2]);
  assert.equal(first.more, true);
  const second = store.page("start-a", first.next, 100, false);
  assert.deepEqual(second.receipts.map((r) => r.sequence), [3, 4, 5]);
  assert.equal(second.more, false);
  assert.equal(second.evictedAfterCursor, false);
  const empty = store.page("start-a", second.next, 100, false);
  assert.deepEqual([empty.receipts.length, empty.next, empty.more], [0, second.next, false]);
  for (const bad of [[-1, 10], [0, 0], [0, 101], [1.5, 10]] as const) {
    assert.throws(() => store.page("start-a", bad[0], bad[1], false), ReceiptRejected);
  }
});

test("an eviction past the reader's cursor is reported; one before it is not", () => {
  const store = new ReceiptStore(memorySql());
  store.record("start-a", receipt(1));
  const read = store.page("start-a", 0, 100, false);
  for (let sequence = 2; sequence <= MAX_ROWS + 3; sequence++) store.record("start-a", receipt(sequence));
  const after = store.page("start-a", read.next, 100, false);
  assert.equal(after.evictedAfterCursor, true, "receipts 2.. were evicted unread");
  const caughtUp = store.page("start-a", MAX_ROWS, 100, false);
  assert.equal(caughtUp.evictedAfterCursor, false);
});

test("a page reports conflicts, refused boots and an ended start's unterminated boots", () => {
  const store = new ReceiptStore(memorySql());
  store.record("start-a", receipt(1));
  store.record("start-a", receipt(1, { uptime_seconds: 9 }));
  for (let boot = 1; boot < MAX_BOOTS; boot++) store.record("start-a", receipt(1, { boot_id: boot.toString(16).padStart(32, "0") }));
  assert.throws(() => store.record("start-a", receipt(1, { boot_id: "f".repeat(32) })), ReceiptRejected);
  const page = store.page("start-a", 0, 100, true);
  assert.equal(page.duplicatesConflicting, 1);
  assert.equal(page.refusedBoots, 1);
  assert.equal(page.ended, true);
  assert.ok(page.unterminated.includes(BOOT));
  assert.deepEqual(store.page("start-a", 0, 100, false).unterminated, []);
});
