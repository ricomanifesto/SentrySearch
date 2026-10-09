// Jobs script: one JobRunner Durable Object per release job. It starts the
// release-tools image through its Cloudflare entrypoint, enforces the job's
// deadline with alarms (SIGTERM, then destroy() after a grace period), which
// also covers deadlines beyond the 15-minute monitor() window (H-J1), and
// never reports success on its own: destroy(), a deadline or a resolved
// monitor() leaves sql_outcome "unknown" until the job's own completion
// receipt for the current start exists (job receipts are CF-05).

import { DurableObject } from "cloudflare:workers";
import { boundedBody } from "./shared/bytes";
import { ControlRefused, importPublicKey, ReplayGuard, verifyControl } from "./shared/control";

interface JobsEnv {
  CONTROL_PUBLIC_KEY: string;
  RELEASE_ID: string;
  SELF: DurableObjectNamespace;
  [binding: string]: unknown;
}

const RELEASE_PYTHON = ["/usr/local/bin/python3.11", "-I", "-B", "-m"];
const JOBS = new Set(["bootstrap", "grant", "proof", "reconcile"]);
const PROFILES = new Set(["runtime-release", "search-release"]);
const NAME = /^job-[0-9a-f-]{36}-[a-z0-9-]{1,40}$/;
const GRACE_MS = 30_000;
const MAX_DEADLINE_SECONDS = 6 * 3600;

interface JobRow {
  start_nonce: string;
  job: string;
  profile: string;
  deadline_at: number;
  state: string;
  exit_detail: string | null;
  completion_receipt: string | null;
}

export class JobRunner extends DurableObject<JobsEnv> {
  private readonly replay: ReplayGuard;
  private keyPromise: Promise<CryptoKey> | undefined;

  constructor(ctx: DurableObjectState, env: JobsEnv) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS jobs (start_nonce TEXT PRIMARY KEY, job TEXT NOT NULL, profile TEXT NOT NULL, deadline_at INTEGER NOT NULL, state TEXT NOT NULL, exit_detail TEXT, completion_receipt TEXT)",
    );
    this.replay = new ReplayGuard(ctx.storage.sql);
    ctx.blockConcurrencyWhile(async () => {
      if (ctx.container?.running) this.observe(ctx.container);
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
      if (command.releaseId !== this.env.RELEASE_ID) throw new ControlRefused(409, "command is for another release");
      this.replay.accept(command, now);
      if (request.method === "POST" && action === "run") return Response.json(await this.run(body));
      if (request.method === "GET" && action === "status") return Response.json(this.status());
      throw new ControlRefused(404, "unknown action");
    } catch (error) {
      if (error instanceof ControlRefused) return Response.json({ error: error.message }, { status: error.status });
      if (error instanceof RangeError) return Response.json({ error: "request too large" }, { status: 413 });
      return Response.json({ error: "internal" }, { status: 500 });
    }
  }

  private async run(body: Uint8Array): Promise<Record<string, unknown>> {
    const request = JSON.parse(new TextDecoder().decode(body)) as { job?: unknown; profile?: unknown; deadline_seconds?: unknown };
    const { job, profile, deadline_seconds: deadline } = request;
    if (
      typeof job !== "string" ||
      !JOBS.has(job) ||
      typeof profile !== "string" ||
      !PROFILES.has(profile) ||
      !Number.isSafeInteger(deadline) ||
      (deadline as number) < 1 ||
      (deadline as number) > MAX_DEADLINE_SECONDS
    ) {
      throw new ControlRefused(400, "invalid job request");
    }
    const container = this.ctx.container;
    if (!container) throw new Error("no container binding");
    if (container.running || this.current()) throw new ControlRefused(409, "this job object has already run");
    const image = container.images["release-tools"];
    if (!image) throw new Error("image is not in this version's images map");
    const startNonce = crypto.randomUUID().replaceAll("-", "");
    const env: Record<string, string> = {};
    for (const [name, value] of Object.entries(this.env)) {
      if (name.startsWith("CONTAINER_") && typeof value === "string") env[name.slice("CONTAINER_".length)] = value;
    }
    container.start({
      image,
      entrypoint: [
        "/usr/local/bin/tini", "--", ...RELEASE_PYTHON, "sentrysearch_cloudflare.cfinit", "start", "--profile", profile, "--",
        ...RELEASE_PYTHON, "release_tools", job,
      ],
      enableInternet: false,
      env,
      labels: { release_id: this.env.RELEASE_ID, start_nonce: startNonce, job },
    });
    const deadlineAt = Date.now() + (deadline as number) * 1000;
    this.ctx.storage.sql.exec(
      "INSERT INTO jobs (start_nonce, job, profile, deadline_at, state) VALUES (?, ?, ?, ?, 'running')",
      startNonce,
      job,
      profile,
      deadlineAt,
    );
    this.observe(container);
    await this.ctx.storage.setAlarm(deadlineAt);
    return { start_nonce: startNonce, deadline_at: deadlineAt };
  }

  private observe(container: Container): void {
    const nonce = this.current()?.start_nonce;
    if (!nonce) return;
    container.monitor().then(
      () => this.finish(nonce, "exited", "exit 0"),
      (error: unknown) => this.finish(nonce, "exited", String(error).slice(0, 200)),
    );
  }

  private finish(startNonce: string, state: string, detail: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE jobs SET state = ?, exit_detail = ? WHERE start_nonce = ? AND state IN ('running', 'signalled')",
      state,
      detail,
      startNonce,
    );
  }

  async alarm(): Promise<void> {
    const container = this.ctx.container;
    const row = this.current();
    if (!container || !row || !container.running) return;
    if (row.state === "running" && Date.now() >= row.deadline_at) {
      container.signal(15);
      this.ctx.storage.sql.exec("UPDATE jobs SET state = 'signalled', exit_detail = 'deadline' WHERE start_nonce = ?", row.start_nonce);
      await this.ctx.storage.setAlarm(Date.now() + GRACE_MS);
      return;
    }
    if (row.state === "signalled") {
      await container.destroy(new Error("job deadline exceeded"));
      this.ctx.storage.sql.exec("UPDATE jobs SET state = 'destroyed' WHERE start_nonce = ?", row.start_nonce);
      return;
    }
    await this.ctx.storage.setAlarm(row.deadline_at);
  }

  private status(): Record<string, unknown> {
    const row = this.current();
    if (!row) return { state: "none" };
    // Success needs the current start's completion receipt; nothing else proves it.
    const succeeded = row.completion_receipt !== null && row.state === "exited" && row.exit_detail === "exit 0";
    return { ...row, sql_outcome: succeeded ? "applied" : "unknown" };
  }
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<JobsEnv>;
