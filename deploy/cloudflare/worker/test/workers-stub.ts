// Stand-in for `cloudflare:workers` when the Durable Object classes run under
// node in the lifecycle tests: only construction is modelled.
export class DurableObject<Env = unknown> {
  constructor(
    protected readonly ctx: DurableObjectState,
    protected readonly env: Env,
  ) {}
}

export class WorkerEntrypoint<Env = unknown, Props = unknown> {
  constructor(
    protected readonly ctx: ExecutionContext<Props>,
    protected readonly env: Env,
  ) {}
}
