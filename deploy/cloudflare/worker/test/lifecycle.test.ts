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
  async interceptOutboundHttp(host: string, binding: { props: { startNonce: string } }) {
    await tick(); // a real binding call yields, letting other requests in
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
    exports: { Evidence: ({ props }: { props: unknown }) => ({ props }), RuntimeRelay: ({ props }: { props: unknown }) => ({ props }) },
    waitUntil() {},
  };
}

const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const publicKey = btoa(String.fromCharCode(...new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer)));
const env = () => ({
  CONTROL_PUBLIC_KEY: publicKey,
  RELEASE_ID: RELEASE,
  SELF: { idFromName, idFromString: (value: string) => new Id(value) },
  CONTAINER_SETTING: "1",
});

let commands = 0;
async function signed(method: string, target: string, action: string, body = ""): Promise<Request> {
  const command: ControlCommand = {
    method,
    target,
    action,
    bodySha256: await sha256Hex(body),
    releaseId: RELEASE,
    session: "session-1",
    fence: "etag-1",
    commandId: `command-${++commands}`,
    expiresAt: Math.floor(now / 1000) + 60,
  };
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, canonicalBytes(command)));
  const headers = new Headers({
    "x-sentry-command-id": command.commandId,
    "x-sentry-release-id": RELEASE,
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
  const started = await json(await service.fetch(await signed("POST", "worker/worker-0", "start")));
  assert.equal(started.started, true);
  return { ctx, service, container, nonce: started.start_nonce as string };
}

async function startedJob(job: string, deadlineSeconds: number) {
  const container = new FakeContainer();
  const name = `job-${RELEASE}-${job}`;
  const ctx = state(name, container);
  const runner = new JobRunner(ctx as Any, env() as Any);
  const body = JSON.stringify({ job, profile: "runtime-release", deadline_seconds: deadlineSeconds });
  const response = await runner.fetch(await signed("POST", `jobs/${name}`, "run", body));
  assert.equal(response.status, 200);
  const status = async () => json(await runner.fetch(await signed("GET", `jobs/${name}`, "status")));
  return { ctx, runner, container, status, ...(await json(response)) } as Any;
}

test("services: a monitor() that settles while the container runs leaves drain enforcement on", async () => {
  const { service, container, ctx } = await startedWorker();
  container.windowEnds();
  await tick();
  const stop = await json(await service.fetch(await signed("POST", "worker/worker-0", "stop")));
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
  const { service, container } = await startedWorker();
  await service.fetch(await signed("POST", "worker/worker-0", "stop"));
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
  const requests = await Promise.all([signed("POST", "worker/worker-0", "start"), signed("POST", "worker/worker-0", "start")]);
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
    assert.equal((await json(await service.fetch(await signed("POST", "worker/worker-0", "start")))).started, true);
    container.exit(0);
    await tick();
  }
  assert.equal(Number(ctx.storage.sql.exec("SELECT COUNT(*) AS n FROM starts").toArray()[0]!.n), 8);
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
  const { ctx, container, runner } = await startedJob("bootstrap", 3600);
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
