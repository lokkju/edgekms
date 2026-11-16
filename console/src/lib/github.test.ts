import { afterEach, describe, expect, it, vi } from "vitest";
import { accountById, loginForId, resolveLogin, resolveRepo } from "./github";

afterEach(() => vi.unstubAllGlobals());

function stub(status: number, body?: unknown) {
  const fetch = vi.fn(
    async (_url: string, _init?: RequestInit) =>
      new Response(body === undefined ? null : JSON.stringify(body), { status }),
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("resolveLogin", () => {
  it("returns the id and canonical login", async () => {
    const fetch = stub(200, { id: 583231, login: "Octocat", type: "User" });
    await expect(resolveLogin("octocat")).resolves.toEqual({ id: 583231, login: "Octocat" });
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/users/octocat");
  });

  it("encodes the login", async () => {
    const fetch = stub(404);
    await resolveLogin("a/../b c");
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/users/a%2F..%2Fb%20c");
  });

  it("trims and strips a leading @", async () => {
    const fetch = stub(200, { id: 1, login: "alice" });
    await resolveLogin("  @alice ");
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/users/alice");
  });

  it("sends no credentials", async () => {
    const fetch = stub(200, { id: 1, login: "alice" });
    await resolveLogin("alice");
    expect(fetch.mock.calls[0]?.[1]?.credentials).toBe("omit");
  });

  it("maps 404 to null", async () => {
    stub(404, { message: "Not Found" });
    await expect(resolveLogin("nobody-here")).resolves.toBeNull();
  });

  it("an empty login is null without a request", async () => {
    const fetch = stub(200, {});
    await expect(resolveLogin("  ")).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("throws on a rate limit or other failure", async () => {
    stub(403, { message: "API rate limit exceeded" });
    await expect(resolveLogin("alice")).rejects.toThrow(/rate limit/);
    stub(500);
    await expect(resolveLogin("alice")).rejects.toThrow(/500/);
  });

  it("throws on a reply without a numeric id", async () => {
    stub(200, { login: "alice" });
    await expect(resolveLogin("alice")).rejects.toThrow();
  });
});

// The cache lives for the page load, so each case uses ids no other case touches.
describe("loginForId", () => {
  it("asks GitHub for the account by id, without credentials", async () => {
    const fetch = stub(200, { id: 101, login: "Bob" });
    await expect(loginForId(101)).resolves.toBe("Bob");
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/user/101");
    expect(fetch.mock.calls[0]?.[1]?.credentials).toBe("omit");
  });

  it("asks once per id, however many callers", async () => {
    const fetch = stub(200, { id: 102, login: "carol" });
    const all = await Promise.all([loginForId(102), loginForId(102)]);
    await loginForId(102);
    expect(all).toEqual(["carol", "carol"]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("fails quietly to null on a 404, a rate limit, a network error or a bad reply", async () => {
    stub(404, { message: "Not Found" });
    await expect(loginForId(103)).resolves.toBeNull();
    stub(403, { message: "API rate limit exceeded" });
    await expect(loginForId(104)).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("offline"))));
    await expect(loginForId(105)).resolves.toBeNull();
    stub(200, { id: 106 });
    await expect(loginForId(106)).resolves.toBeNull();
  });

  it("doesn't ask for an id that isn't a positive integer", async () => {
    const fetch = stub(200, { id: 1, login: "x" });
    await expect(loginForId(0)).resolves.toBeNull();
    await expect(loginForId(1.5)).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("accountById", () => {
  it("reads the account's login, creation date and public repos", async () => {
    const fetch = stub(200, {
      id: 201,
      login: "dana",
      created_at: "2015-03-01T12:00:00Z",
      public_repos: 12,
    });
    await expect(accountById(201)).resolves.toEqual({
      id: 201,
      login: "dana",
      createdMs: Date.UTC(2015, 2, 1, 12),
      publicRepos: 12,
    });
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/user/201");
    expect(fetch.mock.calls[0]?.[1]?.credentials).toBe("omit");
  });

  it("shares one request per id with loginForId", async () => {
    const fetch = stub(200, { id: 202, login: "erin", created_at: "x", public_repos: "many" });
    const [a, login] = await Promise.all([accountById(202), loginForId(202)]);
    expect(a).toEqual({ id: 202, login: "erin", createdMs: null, publicRepos: null });
    expect(login).toBe("erin");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("is null on a 404, a failure, or an id that isn't a positive integer", async () => {
    stub(404, { message: "Not Found" });
    await expect(accountById(203)).resolves.toBeNull();
    stub(403, { message: "API rate limit exceeded" });
    await expect(accountById(204)).resolves.toBeNull();
    const fetch = stub(200, { id: 1, login: "x" });
    await expect(accountById(-1)).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("resolveRepo", () => {
  it("returns the repository and owner ids", async () => {
    const fetch = stub(200, {
      id: 812345678,
      full_name: "Acme/App",
      owner: { id: 1234567, login: "Acme" },
    });
    await expect(resolveRepo("acme", "app")).resolves.toEqual({
      id: 812345678,
      fullName: "Acme/App",
      ownerId: 1234567,
      ownerLogin: "Acme",
    });
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.github.com/repos/acme/app");
    expect(fetch.mock.calls[0]?.[1]?.credentials).toBe("omit");
  });

  it("maps 404 to null, and throws on other failures", async () => {
    stub(404, { message: "Not Found" });
    await expect(resolveRepo("acme", "gone")).resolves.toBeNull();
    stub(403, { message: "API rate limit exceeded" });
    await expect(resolveRepo("acme", "app")).rejects.toThrow(/rate limit/);
  });

  it("throws on a reply without the ids", async () => {
    stub(200, { id: 1, full_name: "a/b" });
    await expect(resolveRepo("a", "b")).rejects.toThrow();
  });
});
