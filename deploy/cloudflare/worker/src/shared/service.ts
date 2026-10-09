// One named Durable Object per service instance (api-0, worker-0, runtime-0),
// owning one container started from the image the Worker version names.
//
// Before start() the object binds http://evidence.internal (and, for the
// worker, http://runtime.internal) to loopback entrypoints created with props
// it alone sets: its own id, the service and the start nonce. Containers
// therefore cannot claim another identity or another start. Every control
// route requires an operator-signed command for this object's name.

import { DurableObject } from "cloudflare:workers";
import { boundedBody } from "./bytes";
import { ControlRefused, importPublicKey, ReplayGuard, verifyControl, type ControlCommand } from "./control";
import { parseReceipt, ReceiptRejected, ReceiptStore } from "./receipts";

export type ServiceName = "api" | "worker" | "runtime";

export interface ServiceEnv {
  /** Base64 Ed25519 public key of the operator's control key (version binding). */
  CONTROL_PUBLIC_KEY: string;
  /** The release this Worker version belongs to (version binding). */
  RELEASE_ID: string;
  /** This script's own namespace, to bind names to object ids. */
  SELF: DurableObjectNamespace;
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

interface StartRow {
  start_nonce: string;
  release_id: string;
  started_at: number;
  state: string;
  exit_detail: string | null;
  drain_deadline: number | null;
}

export abstract class ServiceObject<Env extends ServiceEnv> extends DurableObject<Env> {
  protected abstract readonly spec: ServiceSpec;
  protected readonly receipts: ReceiptStore;
  private readonly replay: ReplayGuard;
  private keyPromise: Promise<CryptoKey> | undefined;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec(
      "CREATE TABLE IF NOT EXISTS starts (start_nonce TEXT PRIMARY KEY, release_id TEXT NOT NULL, started_at INTEGER NOT NULL, state TEXT NOT NULL, exit_detail TEXT, drain_deadline INTEGER)",
    );
    this.receipts = new ReceiptStore(sql);
    this.replay = new ReplayGuard(sql);
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
      if (error instanceof ControlRefused) return Response.json({ error: error.message }, { status: error.status });
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
    if (command.releaseId !== this.env.RELEASE_ID) throw new ControlRefused(409, "command is for another release");
    this.replay.accept(command, now);
    switch (`${request.method} ${action}`) {
      case "POST start":
        return Response.json(await this.start(command));
      case "POST stop":
        return Response.json(await this.stop());
      case "GET status":
        return Response.json(await this.status());
      case "GET receipts": {
        this.reconcile();
        const row = this.current();
        if (!row) return Response.json({ error: "no start" }, { status: 404 });
        return Response.json(this.receipts.view(row.start_nonce, !LIVE.has(row.state)));
      }
    }
    throw new ControlRefused(404, "unknown action");
  }

  private async start(command: ControlCommand): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    if (!container) throw new Error("no container binding");
    const image = container.images[this.spec.image];
    if (!image) throw new Error("image is not in this version's images map");
    this.reconcile();
    const live = this.current();
    if (container.running || (live && LIVE.has(live.state))) return { started: false, start_nonce: live?.start_nonce ?? null };
    // Claim the start before the first await: a second start arriving while
    // the interceptions are being bound sees this row and changes nothing.
    const startNonce = crypto.randomUUID().replaceAll("-", "");
    this.ctx.storage.sql.exec(
      "INSERT INTO starts (start_nonce, release_id, started_at, state) VALUES (?, ?, ?, 'starting')",
      startNonce,
      this.env.RELEASE_ID,
      Date.now(),
    );
    this.forgetOldStarts();
    try {
      // Interception must be configured before start(); on a fresh container,
      // configuring it afterwards broke ingress (local probe).
      await this.intercept(container, startNonce);
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
    return { started: true, start_nonce: startNonce };
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

  private async stop(): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    this.reconcile();
    const row = this.current();
    if (!container?.running || !row || row.state !== "running") return { stopping: false, state: row?.state ?? null };
    container.signal(15); // SIGTERM: tini forwards it to the role, which drains.
    const deadline = Date.now() + this.spec.drainSeconds * 1000;
    this.ctx.storage.sql.exec(
      "UPDATE starts SET state = 'draining', drain_deadline = ? WHERE start_nonce = ? AND state = 'running'",
      deadline,
      row.start_nonce,
    );
    // Keep the object (and so its container) alive through the drain window.
    await this.ctx.storage.setAlarm(Math.min(deadline, Date.now() + KEEPALIVE_MS));
    return { stopping: true, drain_deadline: deadline };
  }

  private async status(): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    this.reconcile();
    const row = this.current();
    return {
      service: this.spec.service,
      running: container?.running ?? false,
      inspect: container?.running ? await container.inspect() : null,
      start: row ?? null,
    };
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
