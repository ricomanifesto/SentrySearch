// The intake behind http://evidence.internal. A container reaches it only
// through the interception its Durable Object configured before start(), and
// the props on that binding (object id, service, start nonce) are the only
// identity used; nothing the container sends can change them.

import { WorkerEntrypoint } from "cloudflare:workers";
import { boundedBody } from "./bytes";
import { MAX_RECEIPT_BYTES } from "./receipts";
import type { EvidenceProps, ServiceEnv } from "./service";

interface ReceiptRecorder {
  recordReceipt(props: EvidenceProps, body: ArrayBuffer): Promise<number>;
}

export class Evidence extends WorkerEntrypoint<ServiceEnv, EvidenceProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/receipts") {
      return new Response(null, { status: 404 });
    }
    if (!props?.objectId || !/^[0-9a-f]{64}$/.test(props.objectId)) return new Response(null, { status: 403 });
    let body: Uint8Array;
    try {
      body = await boundedBody(request, MAX_RECEIPT_BYTES);
    } catch {
      return new Response(null, { status: 413 });
    }
    const owner = this.env.SELF.get(this.env.SELF.idFromString(props.objectId)) as unknown as ReceiptRecorder;
    const status = await owner.recordReceipt(props, body.slice().buffer);
    return new Response(null, { status });
  }
}
