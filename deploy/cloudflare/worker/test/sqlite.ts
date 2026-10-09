// node:sqlite behind the Sql interface the Durable Object code uses.
// @ts-expect-error node:sqlite has no types in this package.
import { DatabaseSync } from "node:sqlite";
import type { Sql } from "../src/shared/control";

export function memorySql(): Sql {
  const db = new DatabaseSync(":memory:");
  return {
    exec(query: string, ...bindings: unknown[]) {
      const statement = db.prepare(query);
      const rows = /^\s*(SELECT|INSERT[\s\S]*RETURNING)/i.test(query) ? statement.all(...bindings) : (statement.run(...bindings), []);
      return { toArray: () => rows as Record<string, unknown>[] };
    },
  };
}
