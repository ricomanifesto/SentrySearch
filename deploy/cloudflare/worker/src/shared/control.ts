// Signed control requests (CF-D016 primitives).
//
// The operator signs canonical bytes with an Ed25519 key whose public half is a
// Worker version binding. A Durable Object accepts a command only if the
// signature verifies, the command is unexpired with a bounded lifetime, it
// names this object as its target, its body matches the signed digest, and its
// command id has never been accepted (an atomic primary-key insert). Which
// release, session and fence may act, and the recovery handover, belong to the
// release controller's authority protocol (CF-05); this module carries those
// values signed and unchanged so that protocol can enforce them.

import { base64ToBytes, sha256Hex } from "./bytes";

export const CONTROL_VERSION = "sentry.control.v1";
export const MAX_LIFETIME_SECONDS = 300;
export const MAX_BODY_BYTES = 16 * 1024;
const FIELD = /^[A-Za-z0-9._:\/-]{1,128}$/;
const HEADERS = {
  commandId: "x-sentry-command-id",
  releaseId: "x-sentry-release-id",
  session: "x-sentry-session",
  fence: "x-sentry-fence",
  expiresAt: "x-sentry-expires-at",
  signature: "x-sentry-signature",
} as const;

export interface ControlCommand {
  method: string;
  target: string;
  action: string;
  bodySha256: string;
  releaseId: string;
  session: string;
  fence: string;
  commandId: string;
  expiresAt: number;
}

export class ControlRefused extends Error {
  constructor(
    readonly status: number,
    reason: string,
  ) {
    super(reason);
  }
}

/** One line per field, in a fixed order, after a version line: no field can contain a newline. */
export function canonicalBytes(command: ControlCommand): Uint8Array {
  for (const [name, value] of Object.entries(command)) {
    if (name === "expiresAt") continue;
    if (name === "bodySha256" ? !/^[0-9a-f]{64}$/.test(String(value)) : !FIELD.test(String(value))) {
      throw new ControlRefused(400, `invalid ${name}`);
    }
  }
  if (!Number.isSafeInteger(command.expiresAt) || command.expiresAt <= 0) throw new ControlRefused(400, "invalid expiresAt");
  const lines = [
    CONTROL_VERSION,
    command.method,
    command.target,
    command.action,
    command.bodySha256,
    command.releaseId,
    command.session,
    command.fence,
    command.commandId,
    String(command.expiresAt),
  ];
  return new TextEncoder().encode(lines.join("\n"));
}

export async function importPublicKey(base64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(base64);
  if (raw.byteLength !== 32) throw new TypeError("Ed25519 public key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

/**
 * Verify a control request for `target` (this object's service and name) and
 * return the command. The caller must then record the command id atomically
 * (see `ReplayGuard`) before acting.
 */
export async function verifyControl(
  request: Request,
  body: Uint8Array,
  target: string,
  action: string,
  key: CryptoKey,
  nowSeconds: number,
): Promise<ControlCommand> {
  const header = (name: string): string => {
    const value = request.headers.get(name);
    if (value === null) throw new ControlRefused(401, `missing ${name}`);
    return value;
  };
  const expires = header(HEADERS.expiresAt);
  if (!/^\d{1,12}$/.test(expires)) throw new ControlRefused(400, "invalid expiry");
  const command: ControlCommand = {
    method: request.method,
    target,
    action,
    bodySha256: await sha256Hex(body),
    releaseId: header(HEADERS.releaseId),
    session: header(HEADERS.session),
    fence: header(HEADERS.fence),
    commandId: header(HEADERS.commandId),
    expiresAt: Number(expires),
  };
  const signed = canonicalBytes(command);
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(header(HEADERS.signature));
  } catch {
    throw new ControlRefused(401, "invalid signature encoding");
  }
  if (signature.byteLength !== 64 || !(await crypto.subtle.verify({ name: "Ed25519" }, key, signature, signed))) {
    throw new ControlRefused(401, "signature does not verify");
  }
  // Checked after the signature, so an unsigned caller learns nothing about timing windows.
  if (command.expiresAt <= nowSeconds) throw new ControlRefused(401, "command expired");
  if (command.expiresAt - nowSeconds > MAX_LIFETIME_SECONDS) throw new ControlRefused(401, "command lifetime too long");
  return command;
}

/** The SQL surface used here: Durable Object SqlStorage, or node:sqlite in tests. */
export interface Sql {
  exec(query: string, ...bindings: unknown[]): { toArray(): Record<string, unknown>[] };
}

/** Atomic at-most-once acceptance of command ids, retained until they expire. */
export class ReplayGuard {
  constructor(private readonly sql: Sql) {
    sql.exec(
      "CREATE TABLE IF NOT EXISTS control_commands (command_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, accepted_at INTEGER NOT NULL)",
    );
  }

  /** Throws `ControlRefused(409)` if the id was already accepted. */
  accept(command: ControlCommand, nowSeconds: number): void {
    // An expired id is refused by verifyControl anyway, so its row can go.
    this.sql.exec("DELETE FROM control_commands WHERE expires_at < ?", nowSeconds);
    const inserted = this.sql
      .exec(
        "INSERT INTO control_commands (command_id, expires_at, accepted_at) VALUES (?, ?, ?) ON CONFLICT (command_id) DO NOTHING RETURNING command_id",
        command.commandId,
        command.expiresAt,
        nowSeconds,
      )
      .toArray();
    if (inserted.length !== 1) throw new ControlRefused(409, "command id already accepted");
  }
}

export const CONTROL_HEADERS = HEADERS;

/** A session's takeover ordinal within its release: a positive decimal integer. */
const FENCE = /^[1-9][0-9]{0,9}$/;
const MAX_FENCE = 2 ** 31 - 1;

/**
 * Which session of this object's release may act (CF-05 authority protocol).
 *
 * The fence is the session's takeover ordinal, derived by the controller from
 * its CAS-ordered journal: each recovery adds one, so a higher fence is a later
 * session of the same release. Release ids, sessions and ETags are compared
 * only for equality, never ordered. A same-release command with a higher fence
 * is adopted (that is how a handover becomes visible here); the same fence must
 * come from the same session; a lower fence is superseded. Authority recorded
 * for another release (written by an older Worker version) is void.
 *
 * Call this in the same synchronous section as the replay check and the
 * effect's claim, so no other request can interleave.
 */
export class Authority {
  constructor(private readonly sql: Sql) {
    sql.exec(
      "CREATE TABLE IF NOT EXISTS control_authority (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), release_id TEXT NOT NULL, fence INTEGER NOT NULL, session TEXT NOT NULL)",
    );
  }

  /** Throws `ControlRefused(409, "superseded")` for an older or conflicting session. */
  admit(command: ControlCommand, releaseId: string): void {
    if (command.releaseId !== releaseId) throw new ControlRefused(409, "command is for another release");
    if (!FENCE.test(command.fence) || Number(command.fence) > MAX_FENCE) throw new ControlRefused(400, "invalid fence");
    const fence = Number(command.fence);
    const row = this.sql.exec("SELECT release_id, fence, session FROM control_authority WHERE singleton = 1").toArray()[0];
    if (!row || row.release_id !== releaseId || fence > Number(row.fence)) {
      this.sql.exec(
        "INSERT INTO control_authority (singleton, release_id, fence, session) VALUES (1, ?, ?, ?) ON CONFLICT (singleton) DO UPDATE SET release_id = excluded.release_id, fence = excluded.fence, session = excluded.session",
        releaseId,
        fence,
        command.session,
      );
      return;
    }
    if (fence === Number(row.fence) && command.session === row.session) return;
    throw new ControlRefused(409, "superseded");
  }

  current(): { releaseId: string; fence: number; session: string } | null {
    const row = this.sql.exec("SELECT release_id, fence, session FROM control_authority WHERE singleton = 1").toArray()[0];
    return row ? { releaseId: String(row.release_id), fence: Number(row.fence), session: String(row.session) } : null;
  }
}
