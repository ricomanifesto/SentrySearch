// Cross-language vectors: commands signed by the Python control client
// (tests/cloudflare_control_vectors.py) must produce the same canonical bytes
// here and verify with verifyControl. The key is a fixture key; it authorizes
// nothing.
// @ts-expect-error node:test has no types in this package.
import { test } from "node:test";
// @ts-expect-error node:assert has no types in this package.
import assert from "node:assert/strict";
// @ts-expect-error node:fs has no types in this package.
import { readFileSync } from "node:fs";
import { canonicalBytes, importPublicKey, verifyControl, type ControlCommand } from "../src/shared/control";
import { base64ToBytes } from "../src/shared/bytes";

interface Vector {
  command: ControlCommand;
  body: string;
  canonical: string;
  signature: string;
}

const fixture = JSON.parse(readFileSync(new URL("../test/fixtures/control-vectors.json", (import.meta as unknown as { url: string }).url), "utf8")) as {
  publicKey: string;
  now: number;
  vectors: Vector[];
};

test("canonical bytes match the Python client's for every vector", () => {
  assert.ok(fixture.vectors.length >= 5);
  for (const vector of fixture.vectors) {
    assert.deepEqual(canonicalBytes(vector.command), base64ToBytes(vector.canonical), vector.command.action);
  }
});

test("every Python-signed vector verifies, and only for its own target, action and body", async () => {
  const key = await importPublicKey(fixture.publicKey);
  for (const vector of fixture.vectors) {
    const { command } = vector;
    const headers = new Headers({
      "x-sentry-command-id": command.commandId,
      "x-sentry-release-id": command.releaseId,
      "x-sentry-session": command.session,
      "x-sentry-fence": command.fence,
      "x-sentry-expires-at": String(command.expiresAt),
      "x-sentry-signature": vector.signature,
    });
    const body = new TextEncoder().encode(vector.body);
    const init = command.method === "GET" ? { method: "GET", headers } : { method: "POST", headers, body: vector.body };
    const request = () => new Request(`http://object/control/${command.action}`, init);
    assert.deepEqual(await verifyControl(request(), body, command.target, command.action, key, fixture.now), command);
    await assert.rejects(verifyControl(request(), body, `${command.target}x`, command.action, key, fixture.now));
    await assert.rejects(verifyControl(request(), new TextEncoder().encode(`${vector.body} `), command.target, command.action, key, fixture.now));
  }
});
