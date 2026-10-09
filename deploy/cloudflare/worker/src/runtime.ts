// Runtime script: the RuntimeService Durable Object runs SentryRuntime behind
// cfinit and relays each tunnel WebSocket to the container's TLS listener with
// getTcpPort().connect() (H-T2). The relay moves opaque bytes; TLS and the
// bearer token stay between the Search worker and the runtime.

import { messageBytes } from "./shared/bytes";
import { ServiceObject, type ServiceEnv, type ServiceSpec } from "./shared/service";

export { Evidence } from "./shared/evidence";

export class RuntimeService extends ServiceObject<ServiceEnv> {
  protected readonly spec: ServiceSpec = {
    service: "runtime",
    image: "runtime",
    entrypoint: ["/app/cfinit", "run", "--", "/app/sentryruntime"],
    receipts: false,
    runtimeTunnel: false,
    port: 8443,
    drainSeconds: 30,
  };

  protected async serve(request: Request, url: URL): Promise<Response> {
    const container = this.ctx.container;
    if (url.pathname !== "/v1/tunnel" || request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return new Response(null, { status: 404 });
    }
    if (!container?.running) return new Response(null, { status: 503 });
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    const socket = container.getTcpPort(this.spec.port).connect("container:8443");
    const writer = socket.writable.getWriter();
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      try {
        server.close(1011, "relay closed");
      } catch {}
      socket.close().catch(() => {});
    };
    // Binary messages may arrive as Blob; keep them in order while converting.
    let pending = Promise.resolve();
    server.addEventListener("message", (event) => {
      pending = pending.then(async () => writer.write(await messageBytes(event.data))).catch(close);
    });
    server.addEventListener("close", close);
    server.addEventListener("error", close);
    this.ctx.waitUntil(
      (async () => {
        const reader = socket.readable.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            server.send(value);
          }
        } catch {}
        close();
      })(),
    );
    return new Response(null, { status: 101, webSocket: client });
  }
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<ServiceEnv>;
