// One named Durable Object per service instance (api-0, worker-0, runtime-0),
// owning one container started from the image the Worker version names.
//
// Before start() the object binds http://evidence.internal (and, for the
// worker, http://runtime.internal) to loopback entrypoints created with props
// it alone sets: its own id, the service and the start nonce. Containers
// therefore cannot claim another identity or another start. Every control
// route requires an operator-signed command for this object's name.
//
// Authority (CF-05): a command for this version's release must carry the
// current or a later session fence (Authority); a command signed for another
// release may only read (status, receipts) or stop the start it names, so the
// next release can quiesce objects still running this one's code. A start is
// at most once per command id, also after its replay row expired.

import { DurableObject } from "cloudflare:workers";
import { boundedBody } from "./bytes";
import {
  AUTHORITY_PROTOCOL,
  Authority,
  ControlRefused,
  importPublicKey,
  ReplayGuard,
  stillValid,
  verifyControl,
  type ControlCommand,
} from "./control";
import { MAX_PAGE, parseReceipt, ReceiptRejected, ReceiptStore } from "./receipts";

export type ServiceName = "api" | "worker" | "runtime";

export interface ServiceEnv {
  /** Base64 Ed25519 public key of the operator's control key (version binding). */
  CONTROL_PUBLIC_KEY: string;
  /** The release this Worker version belongs to (version binding). */
  RELEASE_ID: string;
  /** This script's own namespace, to bind names to object ids. */
  SELF: DurableObjectNamespace;
  /** Version metadata binding: the Worker version this object runs. */
  CF_VERSION_METADATA?: { id?: string };
  /** Container settings: every `CONTAINER_*` string binding, prefix removed. */
  [binding: string]: unknown;
}

export interface EvidenceProps {
  service: ServiceName;
  objectId: string;
  startNonce: string;
}

export interface ServiceSpec {
  service: ServiceName;
  /** Key of the image in this Worker version's `images` map. */
  image: string;
  /** Fixed container command; the image's Cloudflare entrypoint finishes the start. */
  entrypoint: readonly string[];
  /** Post receipts to evidence.internal (the worker) and/or reach runtime.internal. */
  receipts: boolean;
  runtimeTunnel: boolean;
  /** Port the Worker reaches inside the container (API HTTP, runtime TLS). */
  port: number;
  /** SIGTERM-to-destroy window. The platform allows up to 15 minutes. */
  drainSeconds: number;
  /** How status() probes health: an HTTP path on a port, or a TCP connect. */
  health: { kind: "http"; port: number; path: string } | { kind: "tcp" };
}

const KEEPALIVE_MS = 10_000;
const INACTIVITY_TIMEOUT_MS = 5 * 60_000;
const NONCE = /^[0-9a-f]{32}$/;
const NAME = /^[a-z]+-[0-9]{1,3}$/;
/** Starts kept with their receipts; older ones are forgotten when a new start is claimed. */
const KEPT_STARTS = 8;
/** A claimed start whose interceptions never finished binding is abandoned after this. */
const START_CLAIM_MS = 60_000;
/** Row states in which the start owns the container; every other state has ended. */
const LIVE = new Set(["starting", "running", "draining"]);
/** What a command signed for another release may do here. */
const CROSS_RELEASE = new Set(["GET status", "GET receipts", "POST receipts", "POST stop"]);
const HEALTH_TIMEOUT_MS = 2_000;

interface StartRow {
  start_nonce: string;
  release_id: string;
  started_at: number;
  state: string;
  exit_detail: string | null;
  drain_deadline: number | null;
  command_id: string | null;
  version_id: string | null;
  image: string | null;
}

export abstract class ServiceObject<Env extends ServiceEnv> extends DurableObject<Env> {
  protected abstract readonly spec: ServiceSpec;
  protected readonly receipts: ReceiptStore;
  private readonly replay: ReplayGuard;
  private readonly authority: Authority;
  private keyPromise: Promise<CryptoKey> | undefined;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec(
      "CREATE TABLE IF NOT EXISTS starts (start_nonce TEXT PRIMARY KEY, release_id TEXT NOT NULL, started_at INTEGER NOT NULL, state TEXT NOT NULL, exit_detail TEXT, drain_deadline INTEGER, command_id TEXT, version_id TEXT, image TEXT)",
    );
    this.receipts = new ReceiptStore(sql);
    this.replay = new ReplayGuard(sql);
    this.authority = new Authority(sql);
    // After a Durable Object restart the container may still be running:
    // re-arm the inactivity timeout and lifecycle observation (H-L3), and bind
    // the outbound interceptions again for the current start. Locally, the
    // bindings a previous instance created stop answering after a restart
    // (receipt posts fail with EOF), which would silently cut the evidence
    // channel; a gap would hold the release, but the container could not report.
    // A container that ended while no instance watched it is recorded as ended.
    ctx.blockConcurrencyWhile(async () => {
      const container = ctx.container;
      const row = this.current();
      // No start() is in flight in a new instance: a claimed start either
      // reached container.start() (the container runs) or did not.
      if (row?.state === "starting" && container?.running) {
        ctx.storage.sql.exec("UPDATE starts SET state = 'running' WHERE start_nonce = ?", row.start_nonce);
        row.state = "running";
      }
      if (!container?.running) {
        if (row) this.finish(row.start_nonce, "exited", "ended while unobserved");
        return;
      }
      await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
      if (row && ["running", "draining"].includes(row.state)) {
        await this.intercept(container, row.start_nonce);
        this.observe(container, row.start_nonce);
      }
      await this.scheduleAlarm();
    });
  }

  private key(): Promise<CryptoKey> {
    this.keyPromise ??= importPublicKey(this.env.CONTROL_PUBLIC_KEY);
    return this.keyPromise;
  }

  private versionId(): string | null {
    return this.env.CF_VERSION_METADATA?.id ?? null;
  }

  private current(): StartRow | undefined {
    return this.ctx.storage.sql
      .exec("SELECT * FROM starts ORDER BY rowid DESC LIMIT 1")
      .toArray()[0] as StartRow | undefined;
  }

  /**
   * Container environment: `CONTAINER_*` string bindings plus the release. The
   * start nonce stays out: the interception props carry it, and it is the only
   * thing binding a receipt to its start for any holder of this namespace.
   */
  protected containerEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [name, value] of Object.entries(this.env)) {
      if (name.startsWith("CONTAINER_") && typeof value === "string") env[name.slice("CONTAINER_".length)] = value;
    }
    env.SENTRYSEARCH_RELEASE_ID = this.env.RELEASE_ID;
    return env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/control/")) return await this.control(request, url.pathname.slice("/control/".length));
      return await this.serve(request, url);
    } catch (error) {
      if (error instanceof ControlRefused) return Response.json({ error: error.message, code: error.code }, { status: error.status });
      if (error instanceof RangeError) return Response.json({ error: "request too large" }, { status: 413 });
      return Response.json({ error: "internal" }, { status: 500 });
    }
  }

  /** Non-control traffic routed to this object by its own script (ingress, tunnel). */
  protected abstract serve(request: Request, url: URL): Promise<Response>;

  private async control(request: Request, action: string): Promise<Response> {
    const name = request.headers.get("x-sentry-target-name") ?? "";
    // The name must be the one this object was created from, recomputed here,
    // so a command signed for another object cannot be replayed against this one.
    if (!NAME.test(name) || !this.env.SELF.idFromName(name).equals(this.ctx.id)) {
      throw new ControlRefused(403, "target does not name this object");
    }
    const body = await boundedBody(request, 16 * 1024);
    const now = Math.floor(Date.now() / 1000);
    const command = await verifyControl(request, body, `${this.spec.service}/${name}`, action, await this.key(), now);
    const verifiedAt = stillValid(command);
    const route = `${request.method} ${action}`;
    // From here to the effect's claim nothing awaits: authority, replay and
    // the claim are one atomic step against every other request.
    if (command.releaseId === this.env.RELEASE_ID) this.authority.admit(command, this.env.RELEASE_ID);
    else if (!CROSS_RELEASE.has(route)) throw new ControlRefused(409, "command is for another release", "another_release");
    this.replay.accept(command, verifiedAt);
    switch (route) {
      case "POST start":
        return Response.json(await this.start(command, jsonBody(body)));
      case "POST stop":
        return Response.json(await this.stop(jsonBody(body)));
      case "GET status":
        return Response.json(await this.status());
      case "GET receipts": {
        this.reconcile();
        const row = this.current();
        if (!row) return Response.json({ error: "no start" }, { status: 404 });
        return Response.json(this.receipts.view(row.start_nonce, !LIVE.has(row.state)));
      }
      case "POST receipts": {
        this.reconcile();
        const row = this.current();
        const page = jsonBody(body);
        if (!row || page.start_nonce !== row.start_nonce) return Response.json({ error: "no such start" }, { status: 404 });
        const after = Number(page.after ?? 0);
        const limit = Number(page.limit ?? MAX_PAGE);
        try {
          return Response.json(this.receipts.page(row.start_nonce, after, limit, !LIVE.has(row.state)));
        } catch (error) {
          if (error instanceof ReceiptRejected) throw new ControlRefused(400, error.message);
          throw error;
        }
      }
    }
    throw new ControlRefused(404, "unknown action");
  }

  private async start(command: ControlCommand, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    // The controller names the version it deployed; another version here is drift.
    if (Object.keys(body).length !== 2 || body.release_id !== this.env.RELEASE_ID || body.version_id !== this.versionId()) {
      throw new ControlRefused(409, "start does not match this version", "version_mismatch");
    }
    const container = this.ctx.container;
    if (!container) throw new Error("no container binding");
    const image = container.images[this.spec.image];
    if (!image) throw new Error("image is not in this version's images map");
    this.reconcile();
    // At most one start per command id, also after its replay row expired.
    const earlier = this.ctx.storage.sql
      .exec("SELECT * FROM starts WHERE command_id = ?", command.commandId)
      .toArray()[0] as StartRow | undefined;
    if (earlier) return { started: false, replayed: true, ...publicStart(earlier) };
    const live = this.current();
    if (container.running || (live && LIVE.has(live.state))) return { started: false, start_nonce: live?.start_nonce ?? null };
    // Claim the start before the first await: a second start arriving while
    // the interceptions are being bound sees this row and changes nothing.
    const startNonce = crypto.randomUUID().replaceAll("-", "");
    this.ctx.storage.sql.exec(
      "INSERT INTO starts (start_nonce, release_id, started_at, state, command_id, version_id, image) VALUES (?, ?, ?, 'starting', ?, ?, ?)",
      startNonce,
      this.env.RELEASE_ID,
      Date.now(),
      command.commandId,
      this.versionId(),
      imageReference(image),
    );
    this.forgetOldStarts();
    try {
      // Interception must be configured before start(); on a fresh container,
      // configuring it afterwards broke ingress (local probe).
      await this.intercept(container, startNonce);
      // After the await: start only for an unexpired command whose claim is
      // still the current one. An abandoned claim never starts, and the
      // interception goes back to the live start (CF04-R31).
      const claim = this.current();
      if (Math.floor(Date.now() / 1000) >= command.expiresAt || claim?.start_nonce !== startNonce || claim.state !== "starting") {
        this.finish(startNonce, "failed", "start abandoned before the container started");
        if (claim && claim.start_nonce !== startNonce && ["running", "draining"].includes(claim.state)) {
          await this.intercept(container, claim.start_nonce);
        }
        return { started: false, abandoned: true, start_nonce: startNonce };
      }
      container.start({
        image,
        entrypoint: [...this.spec.entrypoint],
        enableInternet: false,
        env: this.containerEnv(),
        labels: { release_id: this.env.RELEASE_ID, start_nonce: startNonce, command_id: command.commandId },
      });
    } catch (error) {
      this.finish(startNonce, "failed", String(error).slice(0, 200));
      throw error;
    }
    this.ctx.storage.sql.exec("UPDATE starts SET state = 'running' WHERE start_nonce = ? AND state = 'starting'", startNonce);
    this.observe(container, startNonce);
    await this.scheduleAlarm();
    // Locally setInactivityTimeout() resolves only once the container has
    // booted (seconds under load); the reply does not wait, and every alarm
    // re-arms it.
    this.ctx.waitUntil(container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS).catch(() => undefined));
    const row = this.current();
    return { started: true, ...publicStart(row!) };
  }

  private forgetOldStarts(): void {
    const old = this.ctx.storage.sql
      .exec("SELECT start_nonce FROM starts ORDER BY rowid DESC LIMIT -1 OFFSET ?", KEPT_STARTS)
      .toArray();
    for (const row of old) {
      this.receipts.forget(String(row.start_nonce));
      this.ctx.storage.sql.exec("DELETE FROM starts WHERE start_nonce = ?", row.start_nonce);
    }
  }

  /** Bind the outbound hosts to loopback entrypoints carrying this start's identity. */
  private async intercept(container: Container, startNonce: string): Promise<void> {
    const props = { service: this.spec.service, objectId: this.ctx.id.toString(), startNonce };
    const loopback = (this.ctx as unknown as { exports: Record<string, (options: { props: unknown }) => Fetcher> }).exports;
    if (this.spec.receipts) await container.interceptOutboundHttp("evidence.internal", loopback.Evidence!({ props }));
    if (this.spec.runtimeTunnel) await container.interceptOutboundHttp("runtime.internal", loopback.RuntimeRelay!({ props }));
  }

  /**
   * Record how a start ended; destroy() alone never proves success. monitor()
   * can settle while the container still runs (its window ends, the object
   * restarts), so only a container that is no longer running ends the start;
   * otherwise the next alarm observes it again and enforcement continues.
   */
  private observe(container: Container, startNonce: string): void {
    this.observing = startNonce;
    const settled = (detail: string) => {
      if (this.observing === startNonce) this.observing = undefined;
      if (!container.running) this.finish(startNonce, "exited", detail);
    };
    container.monitor().then(
      () => settled("exit 0"),
      (error: unknown) => settled(String(error).slice(0, 200)),
    );
  }

  private observing: string | undefined;

  /** End a live start; a start already ended (destroyed, exited) keeps its record. */
  private finish(startNonce: string, state: string, detail: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE starts SET state = ?, exit_detail = ? WHERE start_nonce = ? AND state IN ('starting', 'running', 'draining')",
      state,
      detail,
      startNonce,
    );
  }

  /**
   * A live row whose container is gone ended without an observer; a claim
   * whose interceptions never finished binding is abandoned (a late start()
   * then runs for an ended row and the alarm destroys it).
   */
  private reconcile(): void {
    const row = this.current();
    if (!row || !LIVE.has(row.state) || this.ctx.container?.running) return;
    if (row.state !== "starting") this.finish(row.start_nonce, "exited", "ended while unobserved");
    else if (Date.now() - row.started_at > START_CLAIM_MS) this.finish(row.start_nonce, "failed", "start did not complete");
  }

  /** Drain exactly the start the command names; a stop for an older start changes nothing. */
  private async stop(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    this.reconcile();
    const row = this.current();
    if (!container?.running || !row || row.state !== "running" || body.start_nonce !== row.start_nonce) {
      return { stopping: false, state: row?.state ?? null };
    }
    container.signal(15); // SIGTERM: tini forwards it to the role, which drains.
    const deadline = Date.now() + this.spec.drainSeconds * 1000;
    this.ctx.storage.sql.exec(
      "UPDATE starts SET state = 'draining', drain_deadline = ? WHERE start_nonce = ? AND state = 'running'",
      deadline,
      row.start_nonce,
    );
    // Keep the object (and so its container) alive through the drain window.
    await this.ctx.storage.setAlarm(Math.min(deadline, Date.now() + KEEPALIVE_MS));
    return { stopping: true, start_nonce: row.start_nonce, drain_deadline: deadline };
  }

  private async status(): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    this.reconcile();
    const row = this.current();
    const running = container?.running ?? false;
    return {
      service: this.spec.service,
      control_protocol: AUTHORITY_PROTOCOL,
      object_id: this.ctx.id.toString(),
      release_id: this.env.RELEASE_ID,
      version_id: this.versionId(),
      running,
      image: row?.image ?? null,
      health: running && row?.state === "running" ? await this.health(container!) : "unhealthy",
      inspect: running ? await container!.inspect() : null,
      start: row ? publicStart(row) : null,
    };
  }

  /** A bounded probe of the running container; anything but a clean answer is unhealthy. */
  private async health(container: Container): Promise<string> {
    const probe = this.spec.health;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("health timeout")), HEALTH_TIMEOUT_MS);
    });
    timeout.catch(() => undefined);
    try {
      if (probe.kind === "http") {
        const response = await Promise.race([
          container.getTcpPort(probe.port).fetch(new Request(`http://container${probe.path}`)),
          timeout,
        ]);
        await response.body?.cancel();
        return response.status === 200 ? "healthy" : "unhealthy";
      }
      const socket = container.getTcpPort(this.spec.port).connect(`container:${this.spec.port}`);
      try {
        await Promise.race([socket.opened, timeout]);
      } finally {
        socket.close().catch(() => undefined);
      }
      return "healthy";
    } catch {
      return "unhealthy";
    } finally {
      if (timer !== null) clearTimeout(timer);
    }
  }

  private async scheduleAlarm(): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null) await this.ctx.storage.setAlarm(Date.now() + KEEPALIVE_MS);
  }

  /**
   * Keepalive while the container runs (also while draining), and enforcement
   * keyed on the container itself, not on a recorded state: destroy after the
   * drain window if SIGTERM did not end it, and destroy a container that runs
   * for a start already recorded as ended.
   */
  async alarm(): Promise<void> {
    const container = this.ctx.container;
    if (!container) return;
    this.reconcile();
    const row = this.current();
    if (!container.running || !row) return;
    const now = Date.now();
    const overdue = row.state === "draining" && row.drain_deadline !== null && now >= row.drain_deadline;
    if (overdue || !LIVE.has(row.state)) {
      if (overdue) this.finish(row.start_nonce, "destroyed", "drain deadline exceeded");
      await container.destroy(new Error(overdue ? "drain deadline exceeded" : "container outlived its start"));
      if (container.running) await this.ctx.storage.setAlarm(Date.now() + KEEPALIVE_MS);
      return;
    }
    if (this.observing !== row.start_nonce && row.state !== "starting") this.observe(container, row.start_nonce);
    await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    const next = now + KEEPALIVE_MS;
    await this.ctx.storage.setAlarm(
      row.state === "draining" && row.drain_deadline !== null ? Math.min(row.drain_deadline, next) : next,
    );
  }

  /** RPC from this script's Evidence entrypoint; identity comes only from its props. */
  async recordReceipt(props: EvidenceProps, body: ArrayBuffer): Promise<number> {
    const row = this.current();
    if (
      props.service !== this.spec.service ||
      props.objectId !== this.ctx.id.toString() ||
      !NONCE.test(props.startNonce) ||
      !row ||
      row.start_nonce !== props.startNonce ||
      !["running", "draining"].includes(row.state)
    ) {
      return 403; // Another object, an old start or a stopped one.
    }
    try {
      this.receipts.record(props.startNonce, parseReceipt(new Uint8Array(body), this.env.RELEASE_ID));
    } catch (error) {
      if (error instanceof ReceiptRejected) return 422;
      throw error;
    }
    return 204;
  }
}

/** A control body: a JSON object or nothing (an empty object). */
function jsonBody(body: Uint8Array): Record<string, unknown> {
  if (body.byteLength === 0) return {};
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  } catch {
    throw new ControlRefused(400, "body is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ControlRefused(400, "body is not an object");
  return value as Record<string, unknown>;
}

/** The version's image map entry as a string (production: a digest-pinned reference; unverified, H-V1). */
function imageReference(image: unknown): string {
  return typeof image === "string" ? image : JSON.stringify(image);
}

function publicStart(row: StartRow): Record<string, unknown> {
  return { ...row };
}
