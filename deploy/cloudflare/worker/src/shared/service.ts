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
    // re-arm the inactivity timeout and lifecycle observation (H-L3).
    ctx.blockConcurrencyWhile(async () => {
      const container = ctx.container;
      if (container?.running) {
        await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
        this.observe(container);
        await this.scheduleAlarm();
      }
    });
  }

  private key(): Promise<CryptoKey> {
    this.keyPromise ??= importPublicKey(this.env.CONTROL_PUBLIC_KEY);
    return this.keyPromise;
  }

  private current(): StartRow | undefined {
    return this.ctx.storage.sql
      .exec("SELECT * FROM starts ORDER BY started_at DESC LIMIT 1")
      .toArray()[0] as StartRow | undefined;
  }

  /** Container environment: `CONTAINER_*` string bindings plus the start's own identity. */
  protected containerEnv(startNonce: string): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [name, value] of Object.entries(this.env)) {
      if (name.startsWith("CONTAINER_") && typeof value === "string") env[name.slice("CONTAINER_".length)] = value;
    }
    env.SENTRYSEARCH_RELEASE_ID = this.env.RELEASE_ID;
    env.CLOUDFLARE_START_NONCE = startNonce;
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
        const row = this.current();
        if (!row) return Response.json({ error: "no start" }, { status: 404 });
        return Response.json(this.receipts.view(row.start_nonce));
      }
    }
    throw new ControlRefused(404, "unknown action");
  }

  private async start(command: ControlCommand): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    if (!container) throw new Error("no container binding");
    if (container.running) return { started: false, start_nonce: this.current()?.start_nonce ?? null };
    const startNonce = crypto.randomUUID().replaceAll("-", "");
    const props = { service: this.spec.service, objectId: this.ctx.id.toString(), startNonce };
    const loopback = (this.ctx as unknown as { exports: Record<string, (options: { props: unknown }) => Fetcher> }).exports;
    // Interception must be configured before start(); afterwards it breaks ingress (local probe).
    if (this.spec.receipts) await container.interceptOutboundHttp("evidence.internal", loopback.Evidence!({ props }));
    if (this.spec.runtimeTunnel) await container.interceptOutboundHttp("runtime.internal", loopback.RuntimeRelay!({ props }));
    const image = container.images[this.spec.image];
    if (!image) throw new Error("image is not in this version's images map");
    container.start({
      image,
      entrypoint: [...this.spec.entrypoint],
      enableInternet: false,
      env: this.containerEnv(startNonce),
      labels: { release_id: this.env.RELEASE_ID, start_nonce: startNonce, command_id: command.commandId },
    });
    this.ctx.storage.sql.exec(
      "INSERT INTO starts (start_nonce, release_id, started_at, state) VALUES (?, ?, ?, 'running')",
      startNonce,
      this.env.RELEASE_ID,
      Date.now(),
    );
    await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    this.observe(container);
    await this.scheduleAlarm();
    return { started: true, start_nonce: startNonce };
  }

  /** Record how the current start ended; destroy() alone never proves success. */
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
      "UPDATE starts SET state = ?, exit_detail = ? WHERE start_nonce = ? AND state IN ('running', 'draining')",
      state,
      detail,
      startNonce,
    );
  }

  private async stop(): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
    const row = this.current();
    if (!container?.running || !row) return { stopping: false };
    container.signal(15); // SIGTERM: tini forwards it to the role, which drains.
    const deadline = Date.now() + this.spec.drainSeconds * 1000;
    this.ctx.storage.sql.exec(
      "UPDATE starts SET state = 'draining', drain_deadline = ? WHERE start_nonce = ? AND state = 'running'",
      deadline,
      row.start_nonce,
    );
    await this.ctx.storage.setAlarm(deadline);
    return { stopping: true, drain_deadline: deadline };
  }

  private async status(): Promise<Record<string, unknown>> {
    const container = this.ctx.container;
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

  /** Keepalive while running; destroy after the drain window if SIGTERM did not end it. */
  async alarm(): Promise<void> {
    const container = this.ctx.container;
    const row = this.current();
    if (!container || !row) return;
    if (row.state === "draining" && row.drain_deadline !== null && Date.now() >= row.drain_deadline) {
      if (container.running) {
        await container.destroy(new Error("drain deadline exceeded"));
        this.finish(row.start_nonce, "destroyed", "drain deadline exceeded");
      }
      return;
    }
    if (container.running) {
      await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
      await this.ctx.storage.setAlarm(
        row.state === "draining" && row.drain_deadline !== null ? row.drain_deadline : Date.now() + KEEPALIVE_MS,
      );
    }
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
