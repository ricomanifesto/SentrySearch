// Readiness receipt intake (CF-D015).
//
// A container posts its receipts to http://evidence.internal; the interception
// binding the Durable Object created before start() carries the object's id and
// the start nonce as props, so identity never comes from the receipt or the
// container. Rows are bounded: the oldest are evicted and an eviction watermark
// records what was lost, so a reader can tell "complete" from "complete after
// eviction" and from "gap". Missing history holds the release gate.

import type { Sql } from "./control";

export const RECEIPT_KIND = "sentry.worker-readiness.v1";
export const MAX_RECEIPT_BYTES = 2048;
export const MAX_ROWS = 512;
/** Boot ids per start: one worker process per container start, so a few at most. */
export const MAX_BOOTS = 8;
const PHASES = new Set(["starting", "maintenance", "generation", "evaluation", "idle", "stopped", "unknown"]);
const KEYS = [
  "kind",
  "release_id",
  "boot_id",
  "sequence",
  "observed_at",
  "uptime_seconds",
  "alive",
  "ready",
  "draining",
  "phase",
  "phase_elapsed_seconds",
  "phase_budget_seconds",
  "error_code",
].sort();

export interface Receipt {
  kind: string;
  release_id: string;
  boot_id: string;
  sequence: number;
  observed_at: string;
  uptime_seconds: number;
  alive: boolean;
  ready: boolean;
  draining: boolean;
  phase: string;
  phase_elapsed_seconds: number;
  phase_budget_seconds: number;
  error_code: string | null;
}

export class ReceiptRejected extends Error {}

/** Parse exactly the worker's schema v1 receipt for this release; anything else is rejected. */
export function parseReceipt(body: Uint8Array, releaseId: string): Receipt {
  if (body.byteLength === 0 || body.byteLength > MAX_RECEIPT_BYTES) throw new ReceiptRejected("receipt size");
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    throw new ReceiptRejected("receipt is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ReceiptRejected("receipt shape");
  const receipt = value as Record<string, unknown>;
  if (JSON.stringify(Object.keys(receipt).sort()) !== JSON.stringify(KEYS)) throw new ReceiptRejected("receipt fields");
  const number = (key: string) => typeof receipt[key] === "number" && Number.isFinite(receipt[key]) && (receipt[key] as number) >= 0;
  if (
    receipt.kind !== RECEIPT_KIND ||
    receipt.release_id !== releaseId ||
    typeof receipt.boot_id !== "string" ||
    !/^[0-9a-f]{32}$/.test(receipt.boot_id) ||
    !Number.isSafeInteger(receipt.sequence) ||
    (receipt.sequence as number) < 1 ||
    typeof receipt.observed_at !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(receipt.observed_at) ||
    !number("uptime_seconds") ||
    !number("phase_elapsed_seconds") ||
    !number("phase_budget_seconds") ||
    typeof receipt.alive !== "boolean" ||
    typeof receipt.ready !== "boolean" ||
    typeof receipt.draining !== "boolean" ||
    typeof receipt.phase !== "string" ||
    !PHASES.has(receipt.phase) ||
    !(receipt.error_code === null || (typeof receipt.error_code === "string" && /^[a-z_]{1,64}$/.test(receipt.error_code)))
  ) {
    throw new ReceiptRejected("receipt values");
  }
  return receipt as unknown as Receipt;
}

export interface ReceiptView {
  startNonce: string;
  /** The start has ended: its history must close with a "stopped" receipt per boot. */
  ended: boolean;
  receipts: Receipt[];
  /** Highest sequence evicted per boot, or 0. */
  evictedThrough: Record<string, number>;
  /** Missing sequences (bounded list) between 1 and the highest received, beyond eviction. */
  gaps: Record<string, number[]>;
  duplicatesConflicting: number;
  /** Receipts refused because the start already had MAX_BOOTS boot ids. */
  refusedBoots: number;
  /** Boots whose last receipt is not "stopped", for an ended start. */
  unterminated: string[];
  complete: boolean;
}

export class ReceiptStore {
  constructor(private readonly sql: Sql) {
    sql.exec(
      "CREATE TABLE IF NOT EXISTS receipts (start_nonce TEXT NOT NULL, boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, received_order INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (start_nonce, boot_id, sequence))",
    );
    sql.exec(
      "CREATE TABLE IF NOT EXISTS receipt_meta (start_nonce TEXT NOT NULL, boot_id TEXT NOT NULL, evicted_through INTEGER NOT NULL DEFAULT 0, conflicts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (start_nonce, boot_id))",
    );
    sql.exec("CREATE TABLE IF NOT EXISTS receipt_starts (start_nonce TEXT PRIMARY KEY, refused_boots INTEGER NOT NULL DEFAULT 0)");
  }

  /** Drop everything kept for a start (the owner keeps only its recent starts). */
  forget(startNonce: string): void {
    for (const table of ["receipts", "receipt_meta", "receipt_starts"]) {
      this.sql.exec(`DELETE FROM ${table} WHERE start_nonce = ?`, startNonce);
    }
  }

  /** Store one receipt for the current start; identical redelivery is idempotent. */
  record(startNonce: string, receipt: Receipt): void {
    const body = JSON.stringify(receipt);
    const existing = this.sql
      .exec(
        "SELECT body FROM receipts WHERE start_nonce = ? AND boot_id = ? AND sequence = ?",
        startNonce,
        receipt.boot_id,
        receipt.sequence,
      )
      .toArray();
    this.sql.exec("INSERT INTO receipt_starts (start_nonce) VALUES (?) ON CONFLICT DO NOTHING", startNonce);
    const known = this.sql
      .exec("SELECT 1 FROM receipt_meta WHERE start_nonce = ? AND boot_id = ?", startNonce, receipt.boot_id)
      .toArray();
    if (known.length === 0) {
      // Boot ids are chosen by the container: bound them, and remember the refusal.
      const boots = Number(this.sql.exec("SELECT COUNT(*) AS n FROM receipt_meta WHERE start_nonce = ?", startNonce).toArray()[0]?.n ?? 0);
      if (boots >= MAX_BOOTS) {
        this.sql.exec("UPDATE receipt_starts SET refused_boots = refused_boots + 1 WHERE start_nonce = ?", startNonce);
        throw new ReceiptRejected("too many boot ids for this start");
      }
      this.sql.exec("INSERT INTO receipt_meta (start_nonce, boot_id) VALUES (?, ?)", startNonce, receipt.boot_id);
    }
    if (existing.length > 0) {
      if (existing[0]?.body !== body) {
        this.sql.exec(
          "UPDATE receipt_meta SET conflicts = conflicts + 1 WHERE start_nonce = ? AND boot_id = ?",
          startNonce,
          receipt.boot_id,
        );
      }
      return;
    }
    const meta = this.sql
      .exec("SELECT evicted_through FROM receipt_meta WHERE start_nonce = ? AND boot_id = ?", startNonce, receipt.boot_id)
      .toArray();
    if (Number(meta[0]?.evicted_through ?? 0) >= receipt.sequence) return; // Already evicted history stays evicted.
    const order = Number(this.sql.exec("SELECT COALESCE(MAX(received_order), 0) + 1 AS next FROM receipts").toArray()[0]?.next ?? 1);
    this.sql.exec(
      "INSERT INTO receipts (start_nonce, boot_id, sequence, received_order, body) VALUES (?, ?, ?, ?, ?)",
      startNonce,
      receipt.boot_id,
      receipt.sequence,
      order,
      body,
    );
    this.evict();
  }

  private evict(): void {
    const count = Number(this.sql.exec("SELECT COUNT(*) AS n FROM receipts").toArray()[0]?.n ?? 0);
    if (count <= MAX_ROWS) return;
    const victims = this.sql
      .exec("SELECT start_nonce, boot_id, sequence FROM receipts ORDER BY received_order ASC LIMIT ?", count - MAX_ROWS)
      .toArray();
    for (const victim of victims) {
      this.sql.exec(
        "UPDATE receipt_meta SET evicted_through = MAX(evicted_through, ?) WHERE start_nonce = ? AND boot_id = ?",
        victim.sequence,
        victim.start_nonce,
        victim.boot_id,
      );
      this.sql.exec(
        "DELETE FROM receipts WHERE start_nonce = ? AND boot_id = ? AND sequence <= ?",
        victim.start_nonce,
        victim.boot_id,
        victim.sequence,
      );
    }
  }

  view(startNonce: string, ended: boolean): ReceiptView {
    const rows = this.sql
      .exec("SELECT boot_id, sequence, body FROM receipts WHERE start_nonce = ? ORDER BY boot_id, sequence", startNonce)
      .toArray();
    const metas = this.sql.exec("SELECT boot_id, evicted_through, conflicts FROM receipt_meta WHERE start_nonce = ?", startNonce).toArray();
    const evictedThrough: Record<string, number> = {};
    const gaps: Record<string, number[]> = {};
    let conflicts = 0;
    for (const meta of metas) {
      evictedThrough[String(meta.boot_id)] = Number(meta.evicted_through);
      conflicts += Number(meta.conflicts);
    }
    const byBoot = new Map<string, number[]>();
    const lastPhase = new Map<string, string>();
    const receipts = rows.map((row) => JSON.parse(String(row.body)) as Receipt);
    for (const receipt of receipts) {
      byBoot.set(receipt.boot_id, [...(byBoot.get(receipt.boot_id) ?? []), receipt.sequence]);
      lastPhase.set(receipt.boot_id, receipt.phase); // rows are ordered by sequence within a boot
    }
    for (const [boot, sequences] of byBoot) {
      const present = new Set(sequences);
      const missing: number[] = [];
      for (let expected = (evictedThrough[boot] ?? 0) + 1; expected <= Math.max(...sequences) && missing.length < 64; expected++) {
        if (!present.has(expected)) missing.push(expected);
      }
      if (missing.length > 0) gaps[boot] = missing;
    }
    const refusedBoots = Number(
      this.sql.exec("SELECT refused_boots FROM receipt_starts WHERE start_nonce = ?", startNonce).toArray()[0]?.refused_boots ?? 0,
    );
    // An ended start whose last receipt is not "stopped" may have lost its tail:
    // nothing after the highest received sequence can show up as a gap.
    const unterminated = ended ? [...lastPhase].filter(([, phase]) => phase !== "stopped").map(([boot]) => boot) : [];
    return {
      startNonce,
      ended,
      receipts,
      evictedThrough,
      gaps,
      duplicatesConflicting: conflicts,
      refusedBoots,
      unterminated,
      complete:
        rows.length > 0 &&
        Object.keys(gaps).length === 0 &&
        conflicts === 0 &&
        refusedBoots === 0 &&
        unterminated.length === 0 &&
        Object.values(evictedThrough).every((v) => v === 0),
    };
  }
}
