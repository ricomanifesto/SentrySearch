// Edge script: the only public entry. It forwards product requests to the API
// object and operator control requests to the named object, which verifies the
// signed command itself. Nothing else is routed: the runtime tunnel and the
// evidence intake are reachable only from inside the Workers runtime.

interface EdgeEnv {
  API: DurableObjectNamespace;
  WORKER: DurableObjectNamespace;
  RUNTIME: DurableObjectNamespace;
  JOBS: DurableObjectNamespace;
}

const NAMESPACES = { api: "API", worker: "WORKER", runtime: "RUNTIME", jobs: "JOBS" } as const;

export default {
  async fetch(request: Request, env: EdgeEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      return env.API.getByName("api-0").fetch(new Request(`http://api${url.pathname}${url.search}`, request));
    }
    const match = /^\/control\/(api|worker|runtime|jobs)\/([a-z0-9-]{1,96})\/([a-z]{1,16})$/.exec(url.pathname);
    if (match) {
      const [, service, name, action] = match as unknown as [string, keyof typeof NAMESPACES, string, string];
      const headers = new Headers(request.headers);
      headers.set("x-sentry-target-name", name);
      const forwarded = new Request(`http://${service}/control/${action}`, { method: request.method, headers, body: request.body });
      return env[NAMESPACES[service]].getByName(name).fetch(forwarded);
    }
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<EdgeEnv>;
