// Jobs script: one JobRunner Durable Object per release job. It starts the
// release-tools image through its Cloudflare entrypoint, keeps the object (and
// so the container) alive with a 10-second alarm, enforces the job's deadline
// from that alarm against the container itself (SIGTERM, then destroy() after
// a grace period), which also covers deadlines beyond the 15-minute monitor()
// window (H-J1), and never reports success on its own: destroy(), a deadline
// SIGTERM or a resolved monitor() leaves sql_outcome "unknown" until the job's
// own completion receipt for the current start exists.
//
// CF-05: commands follow the authority protocol (control.ts Authority): a run
// carries this release and a current session fence; another release may only
// read or stop the start it names. The job posts its separately versioned
// receipt to http://evidence.internal, bound before start() to this object's
// id and the start nonce; the intake stores it only if its identity fields
// equal that binding and the start is still current.

import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { boundedBody } from "./shared/bytes";
import { AUTHORITY_PROTOCOL, Authority, ControlRefused, importPublicKey, ReplayGuard, stillValid, verifyControl } from "./shared/control";

interface JobsEnv {
  CONTROL_PUBLIC_KEY: string;
  RELEASE_ID: string;
  SELF: DurableObjectNamespace;
  CF_VERSION_METADATA?: { id?: string };
  [binding: string]: unknown;
}

interface JobProps {
  objectId: string;
  startNonce: string;
  job: string;
}

const RELEASE_PYTHON = ["/usr/local/bin/python3.11", "-I", "-B", "-m"];
/** The closed job table: (phase, database) to the release-tools command and profile. */
const RELEASE_TOOLS_JOBS: Record<string, { kind: string; profile: string }> = {
  "grant runtime": { kind: "grant", profile: "runtime-release" },
  "grant product": { kind: "grant", profile: "search-release" },
  "proof runtime": { kind: "proof", profile: "runtime-release" },
  "proof product": { kind: "proof", profile: "search-release" },
};
const NAME = /^job-[0-9a-f-]{36}-[a-z0-9-]{1,40}$/;
const JOB_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;
const CROSS_RELEASE = new Set(["GET status", "POST receipt", "POST stop"]);
export const JOB_RECEIPT_SCHEMA = "sentry.release-tools.job.cloudflare.v1";
const MAX_JOB_RECEIPT_BYTES = 2048;
const RESULT_KEY = /^[a-z][a-z_]{0,31}$/;
const RESULT_VALUE = /^[A-Za-z0-9_.:,/-]{1,256}$/;
const GRACE_MS = 30_000;
const KEEPALIVE_MS = 10_000;
const INACTIVITY_TIMEOUT_MS = 5 * 60_000;
const MAX_DEADLINE_SECONDS = 6 * 3600;

interface JobRow {
  start_nonce: string;
  job: string;
  profile: string;
  command_id: string | null;
  version_id: string | null;
  image: string | null;
  deadline_at: number;
  state: string;
  exit_detail: string | null;
  /** When the deadline SIGTERM was sent; a signalled job never reads as applied. */
  signalled_at: number | null;
  completion_receipt: string | null;
}

export class JobRunner extends DurableObject<JobsEnv> {
  private readonly replay: ReplayGuard;
  private readonly authority: Authority;
  private keyPromise: Promise<CryptoKey> | undefined;
  private observing: string | undefined;

  constructor(ctx: DurableObjectState, env: JobsEnv) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS jobs (start_nonce TEXT PRIMARY KEY, job TEXT NOT NULL, profile TEXT NOT NULL, deadline_at INTEGER NOT NULL, state TEXT NOT NULL, exit_detail TEXT, signalled_at INTEGER, completion_receipt TEXT, command_id TEXT, version_id TEXT, image TEXT)",
    );
    this.replay = new ReplayGuard(ctx.storage.sql);
    this.authority = new Authority(ctx.storage.sql);
    ctx.blockConcurrencyWhile(async () => {
      const row = this.current();
      if (ctx.container?.running) {
        if (row) this.observe(ctx.container, row.start_nonce);
        await this.keepAlive(ctx.container);
      } else if (row) {
        this.finish(row.start_nonce, "ended while unobserved");
      }
    });
  }

  private current(): JobRow | undefined {
    return this.ctx.storage.sql.exec("SELECT * FROM jobs ORDER BY rowid DESC LIMIT 1").toArray()[0] as JobRow | undefined;
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const action = new URL(request.url).pathname.replace(/^\/control\//, "");
      const name = request.headers.get("x-sentry-target-name") ?? "";
      if (!NAME.test(name) || !this.env.SELF.idFromName(name).equals(this.ctx.id)) {
        throw new ControlRefused(403, "target does not name this object");
      }
      const body = await boundedBody(request, 4096);
      const now = Math.floor(Date.now() / 1000);
      this.keyPromise ??= importPublicKey(this.env.CONTROL_PUBLIC_KEY);
      const command = await verifyControl(request, body, `jobs/${name}`, action, await this.keyPromise, now);
      const verifiedAt = stillValid(command);
      const route = `${request.method} ${action}`;
      // Authority, replay and the run's claim happen without an await between them.
      if (command.releaseId === this.env.RELEASE_ID) this.authority.admit(command, this.env.RELEASE_ID);
      else if (!CROSS_RELEASE.has(route)) throw new ControlRefused(409, "command is for another release", "another_release");
      this.replay.accept(command, verifiedAt);
      if (route === "POST run") return Response.json(await this.run(name, command.commandId, command.expiresAt, body));
      if (route === "GET status") return Response.json(this.status());
      if (route === "POST stop") return Response.json(await this.stop(body));
      if (route === "POST receipt") return Response.json(this.receipt(body));
      throw new ControlRefused(404, "unknown action");
    } catch (error) {
      if (error instanceof ControlRefused) return Response.json({ error: error.message, code: error.code }, { status: error.status });
      if (error instanceof RangeError) return Response.json({ error: "request too large" }, { status: 413 });
      return Response.json({ error: "internal" }, { status: 500 });
    }
  }

  private versionId(): string | null {
    return this.env.CF_VERSION_METADATA?.id ?? null;
  }

  private async run(name: string, commandId: string, expiresAt: number, body: Uint8Array): Promise<Record<string, unknown>> {
    const request = parseObject(body);
    const { job_id: jobId, phase, database, image: imageKey, deadline_seconds: deadline } = request;
    const entry = RELEASE_TOOLS_JOBS[`${String(phase)} ${String(database)}`];
    if (
      Object.keys(request).length !== 5 ||
      typeof jobId !== "string" ||
      !JOB_ID.test(jobId) ||
      name !== `job-${this.env.RELEASE_ID}-${jobId}` ||
      typeof phase !== "string" ||
      typeof database !== "string" ||
      !Number.isSafeInteger(deadline) ||
      (deadline as number) < 1 ||
      (deadline as number) > MAX_DEADLINE_SECONDS
    ) {
      throw new ControlRefused(400, "invalid job request");
    }
    // Migration images have no receipt producer yet (as on AWS): refuse rather
    // than run a job whose success could never be proven.
    if (!entry || imageKey !== "release_tools") throw new ControlRefused(400, "job is not wired on this platform");
    const container = this.ctx.container;
    if (!container) throw new Error("no container binding");
    if (container.running || this.current()) throw new ControlRefused(409, "this job object has already run", "already_run");
    const image = container.images["release-tools"];
    if (!image) throw new Error("image is not in this version's images map");
    const startNonce = crypto.randomUUID().replaceAll("-", "");
    const env = this.jobEnv(jobId, startNonce);
    this.ctx.storage.sql.exec(
      "INSERT INTO jobs (start_nonce, job, profile, deadline_at, state, command_id, version_id, image) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)",
      startNonce,
      jobId,
      entry.profile,
      Date.now() + (deadline as number) * 1000,
      commandId,
      this.versionId(),
      typeof image === "string" ? image : JSON.stringify(image),
    );
    try {
      await this.intercept(container, startNonce, jobId);
      // After the await: the command must still be valid and this run current.
      const claim = this.current();
      if (Math.floor(Date.now() / 1000) >= expiresAt || claim?.start_nonce !== startNonce || claim.state !== "running") {
        // Nothing started: drop the claim, so the job can still run once (CF05-R18).
        this.ctx.storage.sql.exec("DELETE FROM jobs WHERE start_nonce = ?", startNonce);
        return { object_id: this.ctx.id.toString(), start_nonce: startNonce, command_id: commandId, abandoned: true };
      }
      container.start({
        image,
        entrypoint: [
          "/usr/local/bin/tini", "--", ...RELEASE_PYTHON, "sentrysearch_cloudflare.cfinit", "start", "--profile", entry.profile, "--",
          ...RELEASE_PYTHON, "release_tools", entry.kind,
        ],
        enableInternet: false,
        env,
        labels: { release_id: this.env.RELEASE_ID, start_nonce: startNonce, job: jobId, command_id: commandId },
      });
    } catch (error) {
      this.ctx.storage.sql.exec(
        "UPDATE jobs SET state = 'failed', exit_detail = ? WHERE start_nonce = ?",
        String(error).slice(0, 200),
        startNonce,
      );
      throw error;
    }
    const row = this.current()!;
    this.observe(container, startNonce);
    // Locally setInactivityTimeout() resolves only once the container has
    // booted (seconds under load): arm the alarm now and let it settle behind
    // the reply; every alarm re-arms it.
    await this.keepAlive(container, false);
    return { object_id: this.ctx.id.toString(), start_nonce: startNonce, command_id: commandId, deadline_at: row.deadline_at };
  }

  /**
   * The job's environment: shared CONTAINER_* settings, this job's own
   * JOB_<ID>__* settings, and the identity it reports (set here, never by it).
   */
  private jobEnv(jobId: string, startNonce: string): Record<string, string> {
    const env: Record<string, string> = {};
    const own = `JOB_${jobId.toUpperCase().replaceAll("-", "_")}__`;
    for (const [name, value] of Object.entries(this.env)) {
      if (typeof value !== "string") continue;
      if (name.startsWith("CONTAINER_")) env[name.slice("CONTAINER_".length)] = value;
      else if (name.startsWith(own)) env[name.slice(own.length)] = value;
    }
    env.RELEASE_PLATFORM = "cloudflare";
    env.CLOUDFLARE_DURABLE_OBJECT_ID = this.ctx.id.toString();
    env.SENTRY_LAUNCH_NONCE = startNonce;
    return env;
  }

  private async intercept(container: Container, startNonce: string, job: string): Promise<void> {
    const props: JobProps = { objectId: this.ctx.id.toString(), startNonce, job };
    const loopback = (this.ctx as unknown as { exports: Record<string, (options: { props: unknown }) => Fetcher> }).exports;
    await container.interceptOutboundHttp("evidence.internal", loopback.JobEvidence!({ props }));
  }

  /** SIGTERM the start the command names; the alarm destroys it after the grace. */
  private async stop(body: Uint8Array): Promise<Record<string, unknown>> {
    const request = parseObject(body);
    const container = this.ctx.container;
    const row = this.current();
    if (!container?.running || !row || row.state !== "running" || request.start_nonce !== row.start_nonce) {
      return { stopping: false, state: row?.state ?? null };
    }
    container.signal(15);
    const now = Date.now();
    this.ctx.storage.sql.exec(
      "UPDATE jobs SET state = 'signalled', signalled_at = ? WHERE start_nonce = ? AND state = 'running'",
      now,
      row.start_nonce,
    );
    await this.keepAlive(container);
    return { stopping: true, start_nonce: row.start_nonce };
  }

  private receipt(body: Uint8Array): Record<string, unknown> {
    const request = parseObject(body);
    const row = this.current();
    if (!row || request.start_nonce !== row.start_nonce) throw new ControlRefused(404, "no such start");
    return { start_nonce: row.start_nonce, receipt: row.completion_receipt ? JSON.parse(row.completion_receipt) : null };
  }

  /** RPC from the JobEvidence entrypoint; identity comes only from its props. */
  async recordJobReceipt(props: JobProps, body: ArrayBuffer): Promise<number> {
    const row = this.current();
    if (!row || props.objectId !== this.ctx.id.toString() || props.startNonce !== row.start_nonce || props.job !== row.job) {
      return 403;
    }
    if (body.byteLength === 0 || body.byteLength > MAX_JOB_RECEIPT_BYTES) return 413;
    let receipt: Record<string, unknown>;
    try {
      receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body)) as Record<string, unknown>;
    } catch {
      return 422;
    }
    if (!validJobReceipt(receipt, this.env.RELEASE_ID, props)) return 422;
    const canonical = canonicalJson(receipt);
    if (row.completion_receipt !== null) return row.completion_receipt === canonical ? 204 : 409;
    this.ctx.storage.sql.exec(
      "UPDATE jobs SET completion_receipt = ? WHERE start_nonce = ? AND completion_receipt IS NULL",
      canonical,
      row.start_nonce,
    );
    return 204;
  }

  /**
   * Record how the job ended. monitor() can settle while the container still
   * runs (its 15-minute window, an object restart): only a container that is
   * no longer running ends the job; otherwise the alarm observes it again.
   */
  private observe(container: Container, startNonce: string): void {
    this.observing = startNonce;
    const settled = (detail: string) => {
      if (this.observing === startNonce) this.observing = undefined;
      if (!container.running) this.finish(startNonce, detail);
    };
    container.monitor().then(
      () => settled("exit 0"),
      (error: unknown) => settled(String(error).slice(0, 200)),
    );
  }

  /** End a running or signalled job; a deadline SIGTERM stays in its record. */
  private finish(startNonce: string, detail: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE jobs SET exit_detail = CASE WHEN state = 'signalled' THEN 'deadline; ' || ? ELSE ? END, state = 'exited' WHERE start_nonce = ? AND state IN ('running', 'signalled')",
      detail,
      detail,
      startNonce,
    );
  }

  /** Re-arm the next alarm (the earlier of the keepalive and the next deadline step) and the inactivity timeout. */
  private async keepAlive(container: Container, wait = true): Promise<void> {
    const row = this.current();
    if (!row) return;
    const step = row.state === "signalled" && row.signalled_at !== null ? row.signalled_at + GRACE_MS : row.deadline_at;
    await this.ctx.storage.setAlarm(Math.min(step, Date.now() + KEEPALIVE_MS));
    const inactivity = container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    if (wait) await inactivity;
    else this.ctx.waitUntil(inactivity.catch(() => undefined));
  }

  /** Every enforcement step keys on the container itself, never on a recorded exit. */
  async alarm(): Promise<void> {
    const container = this.ctx.container;
    const row = this.current();
    if (!container || !row) return;
    if (!container.running) {
      this.finish(row.start_nonce, "ended while unobserved");
      return;
    }
    const now = Date.now();
    if (row.state === "running" && now >= row.deadline_at) {
      container.signal(15);
      this.ctx.storage.sql.exec(
        "UPDATE jobs SET state = 'signalled', signalled_at = ? WHERE start_nonce = ? AND state = 'running'",
        now,
        row.start_nonce,
      );
    } else if (
      (row.state === "signalled" && row.signalled_at !== null && now >= row.signalled_at + GRACE_MS) ||
      !["running", "signalled"].includes(row.state)
    ) {
      // Past the grace period, or a container still running for a job recorded as ended.
      this.ctx.storage.sql.exec(
        "UPDATE jobs SET state = 'destroyed', exit_detail = 'job deadline exceeded' WHERE start_nonce = ? AND state IN ('running', 'signalled')",
        row.start_nonce,
      );
      await container.destroy(new Error("job deadline exceeded"));
      if (container.running) await this.ctx.storage.setAlarm(Date.now() + KEEPALIVE_MS);
      return;
    }
    if (this.observing !== row.start_nonce) this.observe(container, row.start_nonce);
    await this.keepAlive(container);
  }

  private status(): Record<string, unknown> {
    const before = this.current();
    if (before && !this.ctx.container?.running) this.finish(before.start_nonce, "ended while unobserved");
    const row = this.current();
    const identity = {
      control_protocol: AUTHORITY_PROTOCOL,
      object_id: this.ctx.id.toString(),
      release_id: this.env.RELEASE_ID,
      version_id: this.versionId(),
      running: this.ctx.container?.running ?? false,
    };
    if (!row) return { ...identity, state: "none", job: null };
    // Success needs the current start's completion receipt; nothing else proves it.
    const succeeded =
      row.completion_receipt !== null && row.signalled_at === null && row.state === "exited" && row.exit_detail === "exit 0";
    const { completion_receipt: _receipt, ...fields } = row;
    return { ...identity, ...fields, has_receipt: row.completion_receipt !== null, sql_outcome: succeeded ? "applied" : "unknown", job: fields };
  }
}

/** http://evidence.internal for a job: the interception's props are the only identity. */
export class JobEvidence extends WorkerEntrypoint<JobsEnv, JobProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/job-receipt") return new Response(null, { status: 404 });
    if (!props?.objectId || !/^[0-9a-f]{64}$/.test(props.objectId)) return new Response(null, { status: 403 });
    let body: Uint8Array;
    try {
      body = await boundedBody(request, MAX_JOB_RECEIPT_BYTES);
    } catch {
      return new Response(null, { status: 413 });
    }
    const owner = this.env.SELF.get(this.env.SELF.idFromString(props.objectId)) as unknown as {
      recordJobReceipt(props: JobProps, body: ArrayBuffer): Promise<number>;
    };
    return new Response(null, { status: await owner.recordJobReceipt(props, body.slice().buffer) });
  }
}

function parseObject(body: Uint8Array): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    throw new ControlRefused(400, "body is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ControlRefused(400, "body is not an object");
  return value as Record<string, unknown>;
}

/** JSON with object keys sorted at every depth, so identical receipts compare equal. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Exactly the sentry.release-tools.job.cloudflare.v1 envelope, bound to this start. */
function validJobReceipt(receipt: Record<string, unknown>, releaseId: string, props: JobProps): boolean {
  const keys = ["durable_object_id", "job_id", "launch_nonce", "release_id", "result", "schema", "status"];
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) return false;
  if (JSON.stringify(Object.keys(receipt).sort()) !== JSON.stringify(keys)) return false;
  const result = receipt.result;
  if (typeof result !== "object" || result === null || Array.isArray(result)) return false;
  const entries = Object.entries(result as Record<string, unknown>);
  return (
    receipt.schema === JOB_RECEIPT_SCHEMA &&
    receipt.release_id === releaseId &&
    receipt.job_id === props.job &&
    receipt.durable_object_id === props.objectId &&
    receipt.launch_nonce === props.startNonce &&
    (receipt.status === "succeeded" || receipt.status === "failed") &&
    entries.length <= 16 &&
    entries.every(([key, value]) => RESULT_KEY.test(key) && typeof value === "string" && RESULT_VALUE.test(value))
  );
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<JobsEnv>;
