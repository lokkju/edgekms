import { describe, expect, it } from "vitest";
import { match } from "./router";

describe("match", () => {
  it("matches home, signin and ops", () => {
    expect(match("/")).toEqual({ name: "home", params: {} });
    expect(match("/signin")).toEqual({ name: "signin", params: {} });
    expect(match("/ops")).toEqual({ name: "ops", params: {} });
  });

  it("matches the account page", () => {
    expect(match("/account")).toEqual({ name: "account", params: {} });
  });

  it("matches the invite request page", () => {
    expect(match("/request-invite")).toEqual({ name: "request-invite", params: {} });
  });

  it("matches a tenant with and without a tab", () => {
    expect(match("/t/acme")).toEqual({ name: "tenant", params: { name: "acme" } });
    expect(match("/t/acme/roles")).toEqual({
      name: "tenant",
      params: { name: "acme", tab: "roles" },
    });
  });

  it("decodes path segments", () => {
    expect(match("/t/a%2Db")).toEqual({ name: "tenant", params: { name: "a-b" } });
  });

  it("ignores one trailing slash", () => {
    expect(match("/ops/")).toEqual({ name: "ops", params: {} });
  });

  it("anything else is notfound", () => {
    expect(match("/nope").name).toBe("notfound");
    expect(match("/t").name).toBe("notfound");
    expect(match("/t/a/b/c").name).toBe("notfound");
    expect(match("/t/%E0%A4%A").name).toBe("notfound");
  });
});
