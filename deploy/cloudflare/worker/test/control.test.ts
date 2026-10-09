// @ts-expect-error node:test has no types in this package.
import { test } from "node:test";
// @ts-expect-error node:assert has no types in this package.
import assert from "node:assert/strict";
import { Authority, canonicalBytes, ControlRefused, ReplayGuard, stillValid, verifyControl, type ControlCommand } from "../src/shared/control";
import { sha256Hex } from "../src/shared/bytes";
import { memorySql } from "./sqlite";

const NOW = 1_800_000_000;

async function keys() {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return pair;
}

async function signed(pair: CryptoKeyPair, overrides: Partial<ControlCommand> = {}, body = "{}", target = "worker/worker-0") {
  const command: ControlCommand = {
    method: "POST",
    target,
    action: "start",
    bodySha256: await sha256Hex(body),
    releaseId: "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d21",
    session: "session-1",
    fence: "etag-1",
    commandId: "command-1",
    expiresAt: NOW + 60,
    ...overrides,
  };
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, canonicalBytes(command)));
  const headers = new Headers({
    "x-sentry-command-id": command.commandId,
    "x-sentry-release-id": command.releaseId,
    "x-sentry-session": command.session,
    "x-sentry-fence": command.fence,
    "x-sentry-expires-at": String(command.expiresAt),
    "x-sentry-signature": btoa(String.fromCharCode(...signature)),
  });
  return { command, request: new Request("http://do/control/start", { method: "POST", headers, body }) };
}

async function refusal(promise: Promise<unknown>): Promise<number> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ControlRefused) return error.status;
    throw error;
  }
  return 0;
}

test("a correctly signed command for this target verifies", async () => {
  const pair = await keys();
  const { request, command } = await signed(pair);
  const body = new TextEncoder().encode("{}");
  assert.deepEqual(await verifyControl(request, body, "worker/worker-0", "start", pair.publicKey, NOW), command);
});

test("any change to a signed field, target, action, method or body fails", async () => {
  const pair = await keys();
  const body = new TextEncoder().encode("{}");
  const { request } = await signed(pair);
  assert.equal(await refusal(verifyControl(request.clone(), body, "worker/worker-1", "start", pair.publicKey, NOW)), 401);
  assert.equal(await refusal(verifyControl(request.clone(), body, "worker/worker-0", "stop", pair.publicKey, NOW)), 401);
  assert.equal(await refusal(verifyControl(request.clone(), new TextEncoder().encode("{ }"), "worker/worker-0", "start", pair.publicKey, NOW)), 401);
  const get = new Request(request.url, { method: "GET", headers: request.headers });
  assert.equal(await refusal(verifyControl(get, body, "worker/worker-0", "start", pair.publicKey, NOW)), 401);
  for (const header of ["x-sentry-command-id", "x-sentry-release-id", "x-sentry-session", "x-sentry-fence"]) {
    const headers = new Headers(request.headers);
    headers.set(header, "tampered");
    const tampered = new Request(request.url, { method: "POST", headers });
    assert.equal(await refusal(verifyControl(tampered, body, "worker/worker-0", "start", pair.publicKey, NOW)), 401, header);
  }
  const other = await keys();
  assert.equal(await refusal(verifyControl(request.clone(), body, "worker/worker-0", "start", other.publicKey, NOW)), 401);
});

test("missing headers, expiry and long lifetimes are refused", async () => {
  const pair = await keys();
  const body = new TextEncoder().encode("{}");
  const expired = await signed(pair, { expiresAt: NOW });
  assert.equal(await refusal(verifyControl(expired.request, body, "worker/worker-0", "start", pair.publicKey, NOW)), 401);
  const long = await signed(pair, { expiresAt: NOW + 301 });
  assert.equal(await refusal(verifyControl(long.request, body, "worker/worker-0", "start", pair.publicKey, NOW)), 401);
  const { request } = await signed(pair);
  for (const header of ["x-sentry-signature", "x-sentry-expires-at", "x-sentry-fence"]) {
    const headers = new Headers(request.headers);
    headers.delete(header);
    const missing = new Request(request.url, { method: "POST", headers });
    assert.ok([400, 401].includes(await refusal(verifyControl(missing, body, "worker/worker-0", "start", pair.publicKey, NOW))));
  }
  const { command } = await signed(pair);
  assert.throws(() => canonicalBytes({ ...command, session: "a\nb" }), ControlRefused);
});

test("a command id is accepted at most once until it expires", async () => {
  const pair = await keys();
  const guard = new ReplayGuard(memorySql());
  const { command } = await signed(pair);
  guard.accept(command, NOW);
  assert.throws(() => guard.accept(command, NOW), (error: unknown) => error instanceof ControlRefused && error.status === 409);
  guard.accept({ ...command, commandId: "command-2" }, NOW);
});

const RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d21";
const OTHER_RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d22";

function command(session: string, fence: string, releaseId = RELEASE): ControlCommand {
  return {
    method: "POST", target: "worker/worker-0", action: "start", bodySha256: "0".repeat(64),
    releaseId, session, fence, commandId: `c-${session}-${fence}`, expiresAt: NOW + 60,
  };
}

function refusedWith(fn: () => void): number {
  try {
    fn();
  } catch (error) {
    if (error instanceof ControlRefused) return error.status;
    throw error;
  }
  return 0;
}

test("a later session's higher fence is adopted and the earlier session is then superseded", () => {
  const authority = new Authority(memorySql());
  authority.admit(command("session-a", "1"), RELEASE);
  authority.admit(command("session-a", "1"), RELEASE);
  authority.admit(command("session-b", "2"), RELEASE);
  assert.deepEqual(authority.current(), { releaseId: RELEASE, fence: 2, session: "session-b" });
  assert.equal(refusedWith(() => authority.admit(command("session-a", "1"), RELEASE)), 409);
  assert.equal(refusedWith(() => authority.admit(command("session-z", "2"), RELEASE)), 409);
  authority.admit(command("session-b", "2"), RELEASE);
});

test("fences are integers, never strings or ETags, and another release's authority is void", () => {
  const authority = new Authority(memorySql());
  authority.admit(command("session-a", "9"), RELEASE);
  // "10" sorts before "9" as text; as a fence it is later.
  authority.admit(command("session-c", "10"), RELEASE);
  assert.equal(authority.current()?.fence, 10);
  for (const bad of ["0", "01", "-1", "1.0", "etag-1", "\"abc\"", "2147483648", ""]) {
    assert.equal(refusedWith(() => authority.admit(command("session-x", bad), RELEASE)), 400, bad);
  }
  assert.equal(refusedWith(() => authority.admit(command("session-x", "99", OTHER_RELEASE), RELEASE)), 409);
  // A newer Worker version (another release) starts afresh at any fence.
  authority.admit(command("session-n", "1", OTHER_RELEASE), OTHER_RELEASE);
  assert.deepEqual(authority.current(), { releaseId: OTHER_RELEASE, fence: 1, session: "session-n" });
});

test("a command that expired while it was verified is refused before it acts", () => {
  const realNow = Date.now;
  try {
    Date.now = () => NOW * 1000;
    assert.equal(stillValid(command("session-a", "1")), NOW);
    Date.now = () => (NOW + 60) * 1000;
    assert.equal(refusedWith(() => stillValid(command("session-a", "1"))), 401);
  } finally {
    Date.now = realNow;
  }
});
