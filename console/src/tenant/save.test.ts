import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../lib/config";
import { saveConfig } from "./save";

const config: Config = { root_id: "r_1", keys: {}, mounts: {}, roles: {}, policies: {} };
let calls: { url: string; init: RequestInit }[];

function respond(status: number, body?: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(body === undefined ? null : JSON.stringify(body), { status });
    }),
  );
}

beforeEach(() => {
  calls = [];
  vi.stubGlobal("location", { pathname: "/t/acme", assign: vi.fn() });
});
afterEach(() => vi.unstubAllGlobals());

describe("saveConfig", () => {
  it("PUTs the whole config with If-Match and returns the new version", async () => {
    respond(200, { data: { config_version: 8 } });
    await expect(saveConfig("acme", config, 7)).resolves.toEqual({ ok: true, version: 8 });
    expect(calls[0]?.url).toBe("/api/v1/tenants/acme/config");
    expect(calls[0]?.init.method).toBe("PUT");
    expect(new Headers(calls[0]?.init.headers).get("If-Match")).toBe('"7"');
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual(config);
  });

  it("takes a 204 as success at the next version", async () => {
    respond(204);
    await expect(saveConfig("acme", config, 7)).resolves.toEqual({ ok: true, version: 8 });
  });

  it("maps 409 to a conflict", async () => {
    respond(409, { errors: ["config version mismatch"] });
    await expect(saveConfig("acme", config, 7)).resolves.toEqual({ ok: false, conflict: true });
  });

  it("maps 400 to the server's first message", async () => {
    respond(400, { errors: ["invalid config: roles.ci: a JWT role needs bound_claims", "x"] });
    await expect(saveConfig("acme", config, 7)).resolves.toEqual({
      ok: false,
      message: "invalid config: roles.ci: a JWT role needs bound_claims",
    });
  });

  it("maps a plain 403 to its message", async () => {
    respond(403, { errors: ["permission denied"] });
    await expect(saveConfig("acme", config, 7)).resolves.toEqual({
      ok: false,
      message: "permission denied",
    });
  });
});
