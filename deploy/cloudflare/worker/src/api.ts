// API script: the ApiService Durable Object runs the Search API role and is the
// only object the edge forwards product traffic to. The API never receives
// runtime credentials and has no runtime.internal interception.

import { ServiceObject, type ServiceEnv, type ServiceSpec } from "./shared/service";

export { Evidence } from "./shared/evidence";

const PYTHON = "/app/.venv/bin/python";

export class ApiService extends ServiceObject<ServiceEnv> {
  protected readonly spec: ServiceSpec = {
    service: "api",
    image: "search",
    entrypoint: ["/usr/local/bin/tini", "--", PYTHON, "-P", "-m", "sentrysearch_cloudflare.cfinit", "start", "--profile", "search", "--", PYTHON, "/app/run_api.py"],
    receipts: false,
    runtimeTunnel: false,
    port: 8001,
    drainSeconds: 30,
  };

  protected async serve(request: Request, url: URL): Promise<Response> {
    const container = this.ctx.container;
    if (!url.pathname.startsWith("/api/") || !container?.running) return new Response(null, { status: 404 });
    // The Search API serves its routes under /api (/api/health, /api/ready, ...).
    return container.getTcpPort(this.spec.port).fetch(new Request(`http://container${url.pathname}${url.search}`, request));
  }
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<ServiceEnv>;
