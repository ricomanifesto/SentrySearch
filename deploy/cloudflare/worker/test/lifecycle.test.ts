// Service and job lifecycles against a fake container and Durable Object state:
// enforcement follows the container, never a recorded exit.
// @ts-expect-error node:test has no types in this package.
import { test } from "node:test";
// @ts-expect-error node:assert has no types in this package.
import assert from "node:assert/strict";
import { canonicalBytes, type ControlCommand } from "../src/shared/control";
import { sha256Hex } from "../src/shared/bytes";
import { JobRunner } from "../src/jobs";
import { WorkerService } from "../src/worker";
import edge from "../src/edge";
import { memorySql } from "./sqlite";

const RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d21";
const VERSION = "7a9e3c1b-2d4f-4a6b-8c0d-1e2f3a4b5c6d";
const START_BODY = JSON.stringify({ release_id: RELEASE, version_id: VERSION });
let now = Date.UTC(2026, 9, 9, 12, 0, 0);
Date.now = () => now;
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

class Id {
  constructor(readonly hex: string) {}
  toString() {
    return this.hex;
  }
  equals(other: Id) {
    return other.hex === this.hex;
  }
}
const idFromName = (name: string) =>
  new Id([...new TextEncoder().encode(name)].map((b) => b.toString(16).padStart(2, "0")).join("").padEnd(64, "0").slice(0, 64));

class FakeContainer {
  running = false;
  images: Record<string, string> = { search: "search", runtime: "runtime", "release-tools": "release-tools" };
  starts: { env: Record<string, string>; labels: Record<string, string> }[] = [];
  signals: number[] = [];
  destroys = 0;
  inactivity = 0;
  intercepts: { host: string; props: { startNonce: string } }[] = [];
  private monitors: { resolve: () => void; reject: (error: unknown) => void }[] = [];
  start(options: { env: Record<string, string>; labels: Record<string, string> }) {
    if (this.running) throw new Error("already running");
    this.running = true;
    this.starts.push(options);
  }
  monitor() {
    return new Promise<void>((resolve, reject) => this.monitors.push({ resolve, reject }));
  }
  signal(signal: number) {
    this.signals.push(signal);
  }
  async destroy(error: unknown) {
    this.destroys++;
    this.running = false;
    this.settle((m) => m.reject(error));
  }
  async setInactivityTimeout() {
    this.inactivity++;
  }
  async inspect() {
    return {};
  }
  /** Next interception: "fail" throws once, "hang" never settles. */
  interceptMode: "ok" | "fail" | "hang" = "ok";
  async interceptOutboundHttp(host: string, binding: { props: { startNonce: string } }) {
    await tick(); // a real binding call yields, letting other requests in
    const mode = this.interceptMode;
    if (mode === "fail") {
      this.interceptMode = "ok";
      throw new Error("binding failed");
    }
    if (mode === "hang") return new Promise<void>(() => {});
    this.intercepts.push({ host, props: binding.props });
  }
  /** monitor() settles without the container stopping (its window ended). */
  windowEnds() {
    this.settle((m) => m.reject(new Error("monitor window elapsed")));
  }
  exit(code: number) {
    this.running = false;
    this.settle((m) => (code === 0 ? m.resolve() : m.reject(new Error(`exit ${code}`))));
  }
  private settle(each: (m: { resolve: () => void; reject: (error: unknown) => void }) => void) {
    const monitors = this.monitors;
    this.monitors = [];
    monitors.forEach(each);
  }
}

function state(name: string, container: FakeContainer, sql = memorySql()) {
  const alarms: number[] = [];
  return {
    id: idFromName(name),
    container,
    alarms,
    storage: {
      sql,
      async getAlarm() {
        return alarms.at(-1) ?? null;
      },
      async setAlarm(at: number) {
        alarms.push(at);
      },
    },
    blockConcurrencyWhile: async (fn: () => Promise<void>) => fn(),
    exports: {
      Evidence: ({ props }: { props: unknown }) => ({ props }),
      RuntimeRelay: ({ props }: { props: unknown }) => ({ props }),
      JobEvidence: ({ props }: { props: unknown }) => ({ props }),
    },
    waitUntil() {},
  };
}

const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const publicKey = btoa(String.fromCharCode(...new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer)));
const env = () => ({
  CONTROL_PUBLIC_KEY: publicKey,
  RELEASE_ID: RELEASE,
  SELF: { idFromName, idFromString: (value: string) => new Id(value) },
  CF_VERSION_METADATA: { id: VERSION },
  CONTAINER_SETTING: "1",
});

let commands = 0;
async function signed(
  method: string,
  target: string,
  action: string,
  body = "",
  authority: { releaseId?: string; session?: string; fence?: string; commandId?: string; expiresAt?: number } = {},
): Promise<Request> {
  const command: ControlCommand = {
    method,
    target,
    action,
    bodySha256: await sha256Hex(body),
    releaseId: authority.releaseId ?? RELEASE,
    session: authority.session ?? "session-1",
    fence: authority.fence ?? "1",
    commandId: authority.commandId ?? `command-${++commands}`,
    expiresAt: authority.expiresAt ?? Math.floor(now / 1000) + 60,
  };
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, canonicalBytes(command)));
  const headers = new Headers({
    "x-sentry-command-id": command.commandId,
    "x-sentry-release-id": command.releaseId,
    "x-sentry-session": command.session,
    "x-sentry-fence": command.fence,
    "x-sentry-expires-at": String(command.expiresAt),
    "x-sentry-signature": btoa(String.fromCharCode(...signature)),
    "x-sentry-target-name": target.split("/")[1]!,
  });
  return new Request(`http://do/control/${action}`, { method, headers, body: method === "GET" ? null : body });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const json = async (response: Response): Promise<Any> => response.json();

async function startedWorker(container = new FakeContainer()) {
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  const started = await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)));
  assert.equal(started.started, true);
  return { ctx, service, container, nonce: started.start_nonce as string };
}

function jobBody(job: string, deadlineSeconds: number, phase = job.startsWith("grant") ? "grant" : "proof") {
  return JSON.stringify({ job_id: job, phase, database: "runtime", image: "release_tools", deadline_seconds: deadlineSeconds });
}

async function startedJob(job: string, deadlineSeconds: number) {
  const container = new FakeContainer();
  const name = `job-${RELEASE}-${job}`;
  const ctx = state(name, container);
  const runner = new JobRunner(ctx as Any, env() as Any);
  const body = jobBody(job, deadlineSeconds);
  const response = await runner.fetch(await signed("POST", `jobs/${name}`, "run", body));
  assert.equal(response.status, 200);
  const status = async () => json(await runner.fetch(await signed("GET", `jobs/${name}`, "status")));
  return { ctx, runner, container, status, ...(await json(response)) } as Any;
}

test("services: a monitor() that settles while the container runs leaves drain enforcement on", async () => {
  const { service, container, ctx, nonce } = await startedWorker();
  container.windowEnds();
  await tick();
  const stop = await json(await service.fetch(await signed("POST", "worker/worker-0", "stop", JSON.stringify({ start_nonce: nonce }))));
  assert.equal(stop.stopping, true);
  assert.ok(ctx.alarms.at(-1)! - now <= 10_000, "keepalive through the drain window");
  now = stop.drain_deadline + 1;
  await service.alarm();
  assert.equal(container.destroys, 1);
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.equal(status.start.state, "destroyed");
  assert.equal(status.start.exit_detail, "drain deadline exceeded");
});

test("services: drain that ends with exit 0 is recorded as exited", async () => {
  const { service, container, nonce } = await startedWorker();
  await service.fetch(await signed("POST", "worker/worker-0", "stop", JSON.stringify({ start_nonce: nonce })));
  container.exit(0);
  await tick();
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.deepEqual([status.start.state, status.start.exit_detail], ["exited", "exit 0"]);
  assert.deepEqual(container.signals, [15]);
});

test("services: concurrent starts claim one start and bind evidence to it", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  const requests = await Promise.all([signed("POST", "worker/worker-0", "start", START_BODY), signed("POST", "worker/worker-0", "start", START_BODY)]);
  const results = await Promise.all(requests.map(async (request) => json(await service.fetch(request))));
  const rows = ctx.storage.sql.exec("SELECT start_nonce FROM starts").toArray();
  assert.equal(rows.length, 1);
  assert.deepEqual(results.map((r: Any) => r.started).sort(), [false, true]);
  assert.equal(container.starts.length, 1);
  assert.deepEqual(
    container.intercepts.map((i) => i.props.startNonce),
    [rows[0]!.start_nonce, rows[0]!.start_nonce],
  );
  assert.ok(!Object.values(container.starts[0]!.env).includes(String(rows[0]!.start_nonce)), "nonce stays out of the container");
});

test("services: a restarted object reconciles a container that ended unobserved", async () => {
  const { ctx } = await startedWorker();
  const restarted = new WorkerService(state("worker-0", new FakeContainer(), ctx.storage.sql) as Any, env() as Any);
  await tick();
  const status = await json(await restarted.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.equal(status.running, false);
  assert.deepEqual([status.start.state, status.start.exit_detail], ["exited", "ended while unobserved"]);
});

test("services: a restarted object re-binds evidence for a running container", async () => {
  const { ctx, container, nonce } = await startedWorker();
  const before = container.intercepts.length;
  new WorkerService(state("worker-0", container, ctx.storage.sql) as Any, env() as Any);
  for (let i = 0; i < 5; i++) await tick();
  assert.deepEqual(
    container.intercepts.slice(before).map((i) => [i.host, i.props.startNonce]),
    [
      ["evidence.internal", nonce],
      ["runtime.internal", nonce],
    ],
  );
});

test("services: receipts of an ended start without a stopped receipt are not complete", async () => {
  const { service, container, ctx, nonce } = await startedWorker();
  const props = { service: "worker" as const, objectId: ctx.id.toString(), startNonce: nonce };
  const receipt = (sequence: number, phase = "idle") =>
    new TextEncoder().encode(
      JSON.stringify({
        kind: "sentry.worker-readiness.v1", release_id: RELEASE, boot_id: "b".repeat(32), sequence,
        observed_at: "2026-10-09T12:00:00.000000Z", uptime_seconds: 1, alive: true, ready: true, draining: false, phase,
        phase_elapsed_seconds: 0, phase_budget_seconds: 0, error_code: null,
      }),
    ).buffer as ArrayBuffer;
  for (const sequence of [1, 2]) assert.equal(await service.recordReceipt(props, receipt(sequence)), 204);
  container.exit(137);
  await tick();
  const view = await json(await service.fetch(await signed("GET", "worker/worker-0", "receipts")));
  assert.equal(view.ended, true);
  assert.equal(view.complete, false);
});

test("services: old starts and their receipts are forgotten", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  for (let start = 0; start < 12; start++) {
    now += 1000;
    assert.equal((await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)))).started, true);
    container.exit(0);
    await tick();
  }
  assert.equal(Number(ctx.storage.sql.exec("SELECT COUNT(*) AS n FROM starts").toArray()[0]!.n), 8);
});

test("services: a failed start retried in the same millisecond leaves the retry current", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  container.interceptMode = "fail";
  assert.equal((await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY))).status, 500);
  const retry = await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)));
  assert.equal(retry.started, true);
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.deepEqual([status.start.start_nonce, status.start.state], [retry.start_nonce, "running"]);
  await service.alarm();
  assert.equal(container.destroys, 0);
});

test("services: a start whose interceptions never bind is abandoned after a minute", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  container.interceptMode = "hang";
  void service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY));
  for (let i = 0; i < 3; i++) await tick();
  assert.equal((await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)))).started, false);
  now += 61_000;
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.deepEqual([status.start.state, status.start.exit_detail], ["failed", "start did not complete"]);
  container.interceptMode = "ok";
  assert.equal((await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)))).started, true);
});

test("jobs: a monitor() that settles while the job runs leaves the deadline enforced", async () => {
  const { runner, container, deadline_at, status } = await startedJob("proof", 3600);
  now += 15 * 60_000;
  container.windowEnds();
  await tick();
  assert.equal((await status()).state, "running");
  now = deadline_at + 1;
  await runner.alarm();
  await runner.alarm();
  assert.deepEqual(container.signals, [15]);
  now += 30_000;
  await runner.alarm();
  assert.equal(container.destroys, 1);
  const final = await status();
  assert.deepEqual([final.state, final.sql_outcome], ["destroyed", "unknown"]);
});

test("jobs: a running job keeps its object awake", async () => {
  const started = now;
  const { ctx, container, runner } = await startedJob("proof", 3600);
  assert.ok(ctx.alarms.at(-1)! - started <= 10_000);
  assert.ok(container.inactivity > 0);
  now += 10_000;
  await runner.alarm();
  assert.equal(ctx.alarms.at(-1)! - now, 10_000);
  assert.equal(container.inactivity, 2);
});

test("jobs: a deadline SIGTERM stays in the record after the job exits 0", async () => {
  const { runner, container, deadline_at, status } = await startedJob("grant", 60);
  now = deadline_at + 1;
  await runner.alarm();
  container.exit(0);
  await tick();
  const final = await status();
  assert.equal(final.state, "exited");
  assert.equal(final.exit_detail, "deadline; exit 0");
  assert.notEqual(final.signalled_at, null);
  assert.equal(final.sql_outcome, "unknown");
});

test("edge: every valid job object name is routable", async () => {
  const calls: string[] = [];
  const namespace = { getByName: (name: string) => ({ fetch: () => (calls.push(name), new Response(null, { status: 204 })) }) };
  const name = `job-${RELEASE}-${"r".repeat(40)}`;
  const response = await edge.fetch(
    new Request(`https://edge.test/control/jobs/${name}/run`, { method: "POST" }),
    { API: namespace, WORKER: namespace, RUNTIME: namespace, JOBS: namespace } as Any,
  );
  assert.equal(response.status, 204);
  assert.deepEqual(calls, [name]);
});

// CF-05 authority protocol --------------------------------------------------

const OTHER_RELEASE = "0b6f7d2e-5a64-4c43-9d0b-0a3f4c6e8d22";

test("authority: a later session supersedes an earlier one at the object, whatever the order of arrival", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  // The earlier session's start is signed but delayed in transit.
  const delayed = await signed("POST", "worker/worker-0", "start", START_BODY, { session: "session-a", fence: "1" });
  const status = await service.fetch(await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "2" }));
  assert.equal(status.status, 200);
  const late = await service.fetch(delayed);
  assert.equal(late.status, 409);
  assert.equal((await json(late)).error, "superseded");
  assert.equal(container.starts.length, 0);
  // Fences are integers: "10" is later than "9".
  assert.equal((await service.fetch(await signed("GET", "worker/worker-0", "status", "", { session: "session-c", fence: "10" }))).status, 200);
  assert.equal((await service.fetch(await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "9" }))).status, 409);
});

test("authority: an expired command is refused even at an object that never saw the successor", async () => {
  const service = new WorkerService(state("worker-0", new FakeContainer()) as Any, env() as Any);
  const old = await signed("POST", "worker/worker-0", "start", START_BODY, { session: "session-a", fence: "1" });
  now += 61_000;
  const response = await service.fetch(old);
  assert.equal(response.status, 401);
});

test("authority: another release may only read or stop the start it names", async () => {
  const { service, container, nonce } = await startedWorker();
  const other = { releaseId: OTHER_RELEASE, session: "next-release", fence: "1" };
  const start = await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY, other));
  assert.equal(start.status, 409);
  assert.equal((await service.fetch(await signed("GET", "worker/worker-0", "status", "", other))).status, 200);
  const stale = await json(await service.fetch(await signed("POST", "worker/worker-0", "stop", JSON.stringify({ start_nonce: "f".repeat(32) }), other)));
  assert.equal(stale.stopping, false);
  assert.deepEqual(container.signals, []);
  const stop = await json(await service.fetch(await signed("POST", "worker/worker-0", "stop", JSON.stringify({ start_nonce: nonce }), other)));
  assert.equal(stop.stopping, true);
  assert.deepEqual(container.signals, [15]);
  // Its commands never touched this release's authority.
  assert.equal((await service.fetch(await signed("GET", "worker/worker-0", "status"))).status, 200);
});

test("authority: one start per command id, also after the replay row expired", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  const first = await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY, { commandId: "start-worker-r1" })));
  assert.equal(first.started, true);
  const replay = await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY, { commandId: "start-worker-r1" }));
  assert.equal(replay.status, 409);
  container.exit(1);
  await tick();
  now += 10 * 60_000; // the replay row has expired; the effect row still holds the id
  const again = await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY, { commandId: "start-worker-r1" })));
  assert.deepEqual([again.started, again.replayed, again.start_nonce], [false, true, first.start_nonce]);
  assert.equal(container.starts.length, 1);
});

test("authority: a start naming another version is refused as drift", async () => {
  const container = new FakeContainer();
  const service = new WorkerService(state("worker-0", container) as Any, env() as Any);
  for (const body of [JSON.stringify({ release_id: RELEASE, version_id: "other" }), "{}", JSON.stringify({ release_id: RELEASE })]) {
    assert.equal((await service.fetch(await signed("POST", "worker/worker-0", "start", body))).status, 409, body);
  }
  assert.equal(container.starts.length, 0);
});

test("authority: a claim whose command expired while binding never starts, and evidence returns to the live start", async () => {
  const container = new FakeContainer();
  const ctx = state("worker-0", container);
  const service = new WorkerService(ctx as Any, env() as Any);
  container.interceptMode = "hang";
  const expires = Math.floor(now / 1000) + 30;
  void service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY, { expiresAt: expires }));
  for (let i = 0; i < 3; i++) await tick();
  now += 61_000; // the claim is abandoned and the command has expired
  container.interceptMode = "ok";
  const live = await json(await service.fetch(await signed("POST", "worker/worker-0", "start", START_BODY)));
  assert.equal(live.started, true);
  assert.equal(container.starts.length, 1);
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status")));
  assert.deepEqual([status.start.start_nonce, status.start.state, status.version_id, status.release_id], [live.start_nonce, "running", VERSION, RELEASE]);
  assert.equal(status.object_id, ctx.id.toString());
});

test("receipts: the controller pages a start's receipts from a cursor", async () => {
  const { service, ctx, nonce } = await startedWorker();
  const props = { service: "worker" as const, objectId: ctx.id.toString(), startNonce: nonce };
  const receipt = (sequence: number) =>
    new TextEncoder().encode(
      JSON.stringify({
        kind: "sentry.worker-readiness.v1", release_id: RELEASE, boot_id: "b".repeat(32), sequence,
        observed_at: "2026-10-09T12:00:00.000000Z", uptime_seconds: sequence, alive: true, ready: true, draining: false,
        phase: "idle", phase_elapsed_seconds: 0, phase_budget_seconds: 30, error_code: null,
      }),
    ).buffer as ArrayBuffer;
  for (const sequence of [1, 2, 3]) assert.equal(await service.recordReceipt(props, receipt(sequence)), 204);
  const page = async (body: unknown) => service.fetch(await signed("POST", "worker/worker-0", "receipts", JSON.stringify(body)));
  const first = await json(await page({ start_nonce: nonce, after: 0, limit: 2 }));
  assert.deepEqual([first.receipts.length, first.more], [2, true]);
  const rest = await json(await page({ start_nonce: nonce, after: first.next, limit: 2 }));
  assert.deepEqual([rest.receipts.map((r: Any) => r.sequence), rest.more], [[3], false]);
  assert.equal((await page({ start_nonce: "c".repeat(32), after: 0, limit: 2 })).status, 404);
  assert.equal((await page({ start_nonce: nonce, after: -1, limit: 2 })).status, 400);
});

test("jobs: a run must name its own object, a wired job and the tools image", async () => {
  const container = new FakeContainer();
  const name = `job-${RELEASE}-runtime-grant`;
  const runner = new JobRunner(state(name, container) as Any, env() as Any);
  const run = async (body: unknown) => runner.fetch(await signed("POST", `jobs/${name}`, "run", JSON.stringify(body)));
  const valid = { job_id: "runtime-grant", phase: "grant", database: "runtime", image: "release_tools", deadline_seconds: 60 };
  for (const bad of [
    { ...valid, job_id: "product-grant" },
    { ...valid, phase: "migrate" },
    { ...valid, image: "runtime" },
    { ...valid, extra: 1 },
    { ...valid, deadline_seconds: 0 },
  ]) {
    assert.equal((await run(bad)).status, 400, JSON.stringify(bad));
  }
  assert.equal(container.starts.length, 0);
  const started = await json(await run(valid));
  assert.equal(started.command_id.startsWith("command-"), true);
  const start = container.starts[0]!;
  assert.deepEqual(
    [start.env.RELEASE_PLATFORM, start.env.CLOUDFLARE_DURABLE_OBJECT_ID, start.env.SENTRY_LAUNCH_NONCE],
    ["cloudflare", idFromName(name).toString(), started.start_nonce],
  );
  assert.equal((await run(valid)).status, 409);
});

test("jobs: the receipt intake stores only this start's exact envelope, once", async () => {
  const { runner, ctx, start_nonce: nonce, status, container } = await startedJob("runtime-grant", 600);
  const props = { objectId: ctx.id.toString(), startNonce: nonce, job: "runtime-grant" };
  const envelope = {
    schema: "sentry.release-tools.job.cloudflare.v1", release_id: RELEASE, job_id: "runtime-grant",
    durable_object_id: ctx.id.toString(), launch_nonce: nonce, status: "succeeded", result: { database: "sentryruntime" },
  };
  const post = (value: unknown, as = props) =>
    runner.recordJobReceipt(as, new TextEncoder().encode(JSON.stringify(value)).buffer as ArrayBuffer);
  assert.equal(await post({ ...envelope, launch_nonce: "f".repeat(32) }), 422);
  assert.equal(await post({ ...envelope, task_arn: "arn:aws:ecs:x" }), 422);
  assert.equal(await post({ ...envelope, release_id: OTHER_RELEASE }), 422);
  assert.equal(await post(envelope, { ...props, startNonce: "f".repeat(32) }), 403);
  assert.equal(await post(envelope), 204);
  assert.equal(await post(envelope), 204, "identical redelivery");
  assert.equal(await post({ ...envelope, status: "failed" }), 409);
  container.exit(0);
  await tick();
  const final = await status();
  assert.deepEqual([final.state, final.sql_outcome, final.has_receipt], ["exited", "applied", true]);
  const read = await json(await runner.fetch(await signed("POST", `jobs/job-${RELEASE}-runtime-grant`, "receipt", JSON.stringify({ start_nonce: nonce }))));
  assert.deepEqual(read.receipt, envelope);
});

test("jobs: a stop SIGTERMs only the named start and never makes it applied", async () => {
  const { runner, container, start_nonce: nonce, status } = await startedJob("proof", 3600);
  const name = `job-${RELEASE}-proof`;
  const stop = async (startNonce: string) =>
    json(await runner.fetch(await signed("POST", `jobs/${name}`, "stop", JSON.stringify({ start_nonce: startNonce }))));
  assert.equal((await stop("f".repeat(32))).stopping, false);
  assert.equal((await stop(nonce)).stopping, true);
  assert.deepEqual(container.signals, [15]);
  container.exit(0);
  await tick();
  const final = await status();
  assert.deepEqual([final.state, final.sql_outcome], ["exited", "unknown"]);
  assert.match(final.exit_detail, /^deadline; /);
});

test("refusals carry machine-readable codes and status names the authority protocol", async () => {
  const container = new FakeContainer();
  const service = new WorkerService(state("worker-0", container) as Any, env() as Any);
  const code = async (request: Request) => (await json(await service.fetch(request))).code;
  assert.equal(await code(await signed("POST", "worker/worker-0", "start", JSON.stringify({ release_id: RELEASE, version_id: "x" }))), "version_mismatch");
  await service.fetch(await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "2" }));
  assert.equal(await code(await signed("GET", "worker/worker-0", "status", "", { session: "session-a", fence: "1" })), "superseded");
  assert.equal(await code(await signed("POST", "worker/worker-0", "start", START_BODY, { releaseId: OTHER_RELEASE })), "another_release");
  const once = await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "2", commandId: "same-id" });
  const twice = await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "2", commandId: "same-id" });
  assert.equal((await service.fetch(once)).status, 200);
  assert.equal(await code(twice), "replayed");
  const status = await json(await service.fetch(await signed("GET", "worker/worker-0", "status", "", { session: "session-b", fence: "2" })));
  assert.equal(status.control_protocol, "sentry.authority.v1");
  const name = `job-${RELEASE}-proof`;
  const runner = new JobRunner(state(name, new FakeContainer()) as Any, env() as Any);
  const body = JSON.stringify({ job_id: "proof", phase: "proof", database: "runtime", image: "release_tools", deadline_seconds: 60 });
  assert.equal((await runner.fetch(await signed("POST", `jobs/${name}`, "run", body))).status, 200);
  assert.equal((await json(await runner.fetch(await signed("POST", `jobs/${name}`, "run", body)))).code, "already_run");
  assert.equal((await json(await runner.fetch(await signed("GET", `jobs/${name}`, "status")))).control_protocol, "sentry.authority.v1");
});
