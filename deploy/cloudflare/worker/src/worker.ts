// Worker script: the WorkerService Durable Object runs the Search worker role,
// posts readiness receipts to evidence.internal and reaches the runtime only
// through runtime.internal, a WebSocket relay to the RuntimeService object
// that carries the worker's own TLS session (CF-D012 option P).

import { WorkerEntrypoint } from "cloudflare:workers";
import { ServiceObject, type EvidenceProps, type ServiceEnv, type ServiceSpec } from "./shared/service";

export { Evidence } from "./shared/evidence";

const PYTHON = "/app/.venv/bin/python";

interface WorkerEnv extends ServiceEnv {
  RUNTIME: DurableObjectNamespace;
}

export class WorkerService extends ServiceObject<WorkerEnv> {
  protected readonly spec: ServiceSpec = {
    service: "worker",
    image: "search",
    entrypoint: [
      "/usr/local/bin/tini", "--", PYTHON, "-P", "-m", "sentrysearch_cloudflare.cfinit", "start", "--profile", "search", "--",
      PYTHON, "-m", "dev.run_runtime_worker", "--health-port", "8081",
    ],
    receipts: true,
    runtimeTunnel: true,
    port: 8081,
    drainSeconds: 30,
  };

  protected containerEnv(): Record<string, string> {
    return { ...super.containerEnv(), SENTRYSEARCH_RECEIPT_URL: "http://evidence.internal/v1/receipts" };
  }

  protected async serve(): Promise<Response> {
    return new Response(null, { status: 404 });
  }
}

/** runtime.internal: accept only the worker's WebSocket and hand it to the runtime object. */
export class RuntimeRelay extends WorkerEntrypoint<WorkerEnv, EvidenceProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (
      props?.service !== "worker" ||
      new URL(request.url).pathname !== "/v1/tunnel" ||
      request.headers.get("upgrade")?.toLowerCase() !== "websocket"
    ) {
      return new Response(null, { status: 403 });
    }
    return this.env.RUNTIME.getByName("runtime-0").fetch(new Request("http://runtime/v1/tunnel", request));
  }
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<WorkerEnv>;
