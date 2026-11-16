import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  expiryWarningDelay,
  noteSignIn,
  request,
  sessionStartedAt,
  signIn,
  signOut,
} from "./api";

type Call = { url: string; init: RequestInit };

let calls: Call[];
let assign: ReturnType<typeof vi.fn>;

function reply(status: number, body?: unknown): Response {
  if (body === undefined) return new Response(null, { status });
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function respondWith(res: Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return res;
    }),
  );
}

let replaceState: ReturnType<typeof vi.fn>;

beforeEach(() => {
  calls = [];
  assign = vi.fn();
  replaceState = vi.fn();
  vi.stubGlobal("location", { pathname: "/t/acme/roles", search: "", hash: "", assign });
  vi.stubGlobal("history", { state: null, replaceState });
  // This page load is not a fresh sign-in.
  noteSignIn();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("request", () => {
  it("returns the data member of a 200", async () => {
    respondWith(reply(200, { data: { login: "alice" } }));
    await expect(request("GET", "/me")).resolves.toEqual({ login: "alice" });
    expect(calls[0]?.url).toBe("/api/v1/me");
    expect(calls[0]?.init.credentials).toBe("same-origin");
    expect(calls[0]?.init.method).toBe("GET");
  });

  it("returns undefined on a 204", async () => {
    respondWith(reply(204));
    await expect(request("POST", "/tenants/acme/accept")).resolves.toBeUndefined();
  });

  it("sends a JSON body with its content type", async () => {
    respondWith(reply(200, { data: {} }));
    await request("POST", "/tenants", { body: { name: "alice-x" } });
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(calls[0]?.init.body).toBe('{"name":"alice-x"}');
  });

  it("sends If-Match as a quoted version", async () => {
    respondWith(reply(200, { data: { config_version: 8 } }));
    await request("PUT", "/tenants/acme/config", { body: {}, ifMatch: 7 });
    expect(new Headers(calls[0]?.init.headers).get("If-Match")).toBe('"7"');
  });

  it("sends the user to sign in on 401 no_session", async () => {
    respondWith(reply(401, { errors: ["sign in required"], code: "no_session" }));
    const err = await request("GET", "/me").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reauth).toBe(true);
    expect(assign).toHaveBeenCalledWith("/auth/login?return_to=%2Ft%2Facme%2Froles");
  });

  it("sends the user to sign in on 403 auth_failed", async () => {
    respondWith(reply(403, { errors: ["permission denied"], code: "auth_failed" }));
    await expect(request("GET", "/tenants/acme")).rejects.toBeInstanceOf(ApiError);
    expect(assign).toHaveBeenCalledWith("/auth/login?return_to=%2Ft%2Facme%2Froles");
  });

  it("with reauth off, reports auth_failed without sending the user anywhere", async () => {
    respondWith(reply(403, { errors: ["permission denied"], code: "auth_failed" }));
    const err = (await request("GET", "/invite-requests/mine", { reauth: false }).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("auth_failed");
    expect(err.reauth).toBe(false);
    expect(assign).not.toHaveBeenCalled();
  });

  it("rejects a 403 without a code and leaves the user signed in", async () => {
    respondWith(reply(403, { errors: ["permission denied"] }));
    const err = (await request("GET", "/tenants/acme").catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.code).toBeUndefined();
    expect(err.reauth).toBe(false);
    expect(err.messages).toEqual(["permission denied"]);
    expect(assign).not.toHaveBeenCalled();
  });

  it("rejects a 409 with its status and messages", async () => {
    respondWith(reply(409, { errors: ["config version mismatch"] }));
    const err = (await request("PUT", "/tenants/acme/config", { body: {}, ifMatch: 1 }).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(err.status).toBe(409);
    expect(err.message).toBe("config version mismatch");
  });

  it("rejects a non-JSON error with a generic message", async () => {
    respondWith(new Response("<html>bad gateway</html>", { status: 502 }));
    const err = (await request("GET", "/me").catch((e: unknown) => e)) as ApiError;
    expect(err.status).toBe(502);
    expect(err.messages).toEqual(["request failed (502)"]);
  });
});

describe("signIn and signOut", () => {
  it("signIn navigates to the login route with an encoded return path", () => {
    signIn("/t/a b");
    expect(assign).toHaveBeenCalledWith("/auth/login?return_to=%2Ft%2Fa%20b");
  });

  it("signOut posts to /auth/logout", async () => {
    respondWith(reply(204));
    await signOut();
    expect(calls[0]?.url).toBe("/auth/logout");
    expect(calls[0]?.init.method).toBe("POST");
    expect(calls[0]?.init.credentials).toBe("same-origin");
  });

  it("signOut rejects when the logout didn't complete", async () => {
    respondWith(reply(500, { errors: ["audit log unavailable"] }));
    const err = (await signOut().catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
    expect(assign).not.toHaveBeenCalled();
  });

  it("signOut rejects when the network fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("offline");
      }),
    );
    await expect(signOut()).rejects.toBeInstanceOf(ApiError);
  });
});

describe("the sign-in loop guard", () => {
  function landSignedIn(search: string, hash = "", at = 1_000_000) {
    vi.stubGlobal("location", { pathname: "/t/acme/roles", search, hash, assign });
    vi.spyOn(Date, "now").mockReturnValue(at);
    noteSignIn();
  }

  it("strips signed_in=1 from the address, keeping the rest", () => {
    landSignedIn("?tab=x&signed_in=1", "#k");
    expect(replaceState).toHaveBeenCalledWith(null, "", "/t/acme/roles?tab=x#k");
  });

  it("strips a lone signed_in=1 and its question mark", () => {
    landSignedIn("?signed_in=1");
    expect(replaceState).toHaveBeenCalledWith(null, "", "/t/acme/roles");
  });

  it("leaves an address without the mark alone", () => {
    landSignedIn("?tab=x");
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("an auth_failed right after sign-in reports a failed login instead of signing in again", async () => {
    landSignedIn("?signed_in=1");
    vi.spyOn(Date, "now").mockReturnValue(1_000_000 + 2_000);
    respondWith(reply(403, { errors: ["permission denied"], code: "auth_failed" }));
    const err = (await request("GET", "/me").catch((e: unknown) => e)) as ApiError;
    expect(err.reauth).toBe(true);
    expect(assign).toHaveBeenCalledWith("/signin?error=login_failed");
    expect(assign).not.toHaveBeenCalledWith(expect.stringContaining("/auth/login"));
  });

  it("a no_session right after sign-in reports a failed login too", async () => {
    landSignedIn("?signed_in=1");
    respondWith(reply(401, { errors: ["sign in required"], code: "no_session" }));
    await request("GET", "/me").catch(() => undefined);
    expect(assign).toHaveBeenCalledWith("/signin?error=login_failed");
  });

  it("an auth_failed well after sign-in signs in again", async () => {
    landSignedIn("?signed_in=1");
    vi.spyOn(Date, "now").mockReturnValue(1_000_000 + 11_000);
    respondWith(reply(403, { errors: ["permission denied"], code: "auth_failed" }));
    await request("GET", "/me").catch(() => undefined);
    expect(assign).toHaveBeenCalledWith("/auth/login?return_to=%2Ft%2Facme%2Froles");
  });

  it("an auth_failed without a sign-in mark signs in again", async () => {
    landSignedIn("");
    respondWith(reply(403, { errors: ["permission denied"], code: "auth_failed" }));
    await request("GET", "/me").catch(() => undefined);
    expect(assign).toHaveBeenCalledWith("/auth/login?return_to=%2Ft%2Facme%2Froles");
  });
});

describe("the session expiry warning", () => {
  const MIN = 60_000;

  it("comes 25 minutes after sign-in", () => {
    expect(expiryWarningDelay(1_000_000, 1_000_000)).toBe(25 * MIN);
    expect(expiryWarningDelay(1_000_000, 1_000_000 + 10 * MIN)).toBe(15 * MIN);
  });

  it("comes at once between 25 and 30 minutes", () => {
    expect(expiryWarningDelay(1_000_000, 1_000_000 + 27 * MIN)).toBe(0);
  });

  it("doesn't come when the session start is unknown, or the session is already over", () => {
    expect(expiryWarningDelay(null, 1_000_000)).toBeNull();
    expect(expiryWarningDelay(1_000_000, 1_000_000 + 30 * MIN)).toBeNull();
  });

  it("follows the sign-in mark of this page load", () => {
    vi.stubGlobal("location", { pathname: "/", search: "?signed_in=1", hash: "", assign });
    vi.spyOn(Date, "now").mockReturnValue(5_000);
    noteSignIn();
    expect(sessionStartedAt()).toBe(5_000);
    vi.stubGlobal("location", { pathname: "/", search: "", hash: "", assign });
    noteSignIn();
    expect(sessionStartedAt()).toBeNull();
  });
});
