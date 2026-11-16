import { describe, expect, it } from "vitest";
import {
  GITHUB_ACTIONS_MOUNT,
  MAX_KEY_VERSION,
  addKey,
  raiseMinDecryption,
  rotateKey,
  addMount,
  addPolicy,
  capabilityGrid,
  cleanRole,
  holdsAdmin,
  newKeyId,
  removeMount,
  removePolicy,
  removeRole,
  renameMount,
  setAdmin,
  setCapability,
  upsertRole,
  type Config,
} from "./config";

function base(): Config {
  return {
    root_id: "r_1",
    keys: { default: { id: "k_0000000000000001", latest_version: 1, min_decryption_version: 1 } },
    mounts: { "github-user": { type: "github-user", client_id: "Iv1.abc" } },
    roles: {
      owner: {
        mount: "github-user",
        github_user_ids: [1],
        policies: ["admin", "default-all"],
        token_ttl_secs: 3600,
      },
    },
    policies: {
      admin: { admin: ["token-create", "token-revoke"] },
      "default-all": { keys: { default: ["encrypt", "decrypt", "rewrap", "read"] } },
    },
  };
}

describe("rotation", () => {
  function at(latest: number, min: number): Config {
    const c = base();
    c.keys.default = { id: "k_0000000000000001", latest_version: latest, min_decryption_version: min };
    return c;
  }

  it("rotateKey raises latest_version by one and keeps the rest", () => {
    const c = at(3, 2);
    const next = rotateKey(c, "default");
    expect(next.keys.default).toEqual({
      id: "k_0000000000000001",
      latest_version: 4,
      min_decryption_version: 2,
    });
    expect(c.keys.default?.latest_version).toBe(3);
  });

  it("rotateKey refuses a missing key, and one at the largest version", () => {
    expect(() => rotateKey(base(), "nope")).toThrow(/no key named nope/);
    expect(() => rotateKey(at(MAX_KEY_VERSION, 1), "default")).toThrow(/largest version/);
  });

  it("raiseMinDecryption sets the version, up to latest_version", () => {
    const next = raiseMinDecryption(at(5, 1), "default", 5);
    expect(next.keys.default?.min_decryption_version).toBe(5);
    expect(next.keys.default?.latest_version).toBe(5);
    expect(raiseMinDecryption(at(5, 1), "default", 3).keys.default?.min_decryption_version).toBe(3);
  });

  it("raiseMinDecryption only raises, and never past latest_version", () => {
    expect(() => raiseMinDecryption(at(5, 3), "default", 3)).toThrow(/above 3/);
    expect(() => raiseMinDecryption(at(5, 3), "default", 2)).toThrow(/above 3/);
    expect(() => raiseMinDecryption(at(5, 3), "default", 6)).toThrow(/at most 5/);
    expect(() => raiseMinDecryption(at(5, 3), "default", 4.5)).toThrow(/whole number/);
    expect(() => raiseMinDecryption(at(5, 3), "nope", 4)).toThrow(/no key named nope/);
  });

  it("a rotated key can then retire its old versions", () => {
    const next = raiseMinDecryption(rotateKey(at(1, 1), "default"), "default", 2);
    expect(next.keys.default).toMatchObject({ latest_version: 2, min_decryption_version: 2 });
  });
});

describe("keys", () => {
  it("newKeyId is k_ and 16 lowercase hex digits", () => {
    for (let i = 0; i < 20; i++) expect(newKeyId()).toMatch(/^k_[0-9a-f]{16}$/);
  });

  it("addKey adds a key at versions 1 and 1 without touching the input", () => {
    const c = base();
    const next = addKey(c, "signing");
    expect(next.keys.signing?.id).toMatch(/^k_[0-9a-f]{16}$/);
    expect(next.keys.signing?.latest_version).toBe(1);
    expect(next.keys.signing?.min_decryption_version).toBe(1);
    expect(c.keys.signing).toBeUndefined();
  });

  it("works on a proxied config, as Svelte state hands in", () => {
    const proxied = new Proxy(base(), {});
    expect(addKey(proxied, "signing").keys.signing).toBeDefined();
  });

  it("addKey refuses a duplicate or invalid name", () => {
    expect(() => addKey(base(), "default")).toThrow(/already/);
    expect(() => addKey(base(), "has space")).toThrow(/A-Za-z0-9_-/);
    expect(() => addKey(base(), "")).toThrow();
  });
});

describe("mounts", () => {
  it("GITHUB_ACTIONS_MOUNT has the exact issuer and JWKS URL", () => {
    expect(GITHUB_ACTIONS_MOUNT).toEqual({
      type: "jwt",
      issuer: "https://token.actions.githubusercontent.com",
      jwks_url: "https://token.actions.githubusercontent.com/.well-known/jwks",
    });
  });

  it("addMount adds and refuses a duplicate", () => {
    const next = addMount(base(), "ci", GITHUB_ACTIONS_MOUNT);
    expect(next.mounts.ci).toEqual(GITHUB_ACTIONS_MOUNT);
    expect(() => addMount(next, "ci", { type: "ssh" })).toThrow(/already/);
  });

  it("addMount copies the mount, so later edits don't alias the preset", () => {
    const next = addMount(base(), "ci", GITHUB_ACTIONS_MOUNT);
    expect(next.mounts.ci).not.toBe(GITHUB_ACTIONS_MOUNT);
  });

  it("removeMount throws while a role references it", () => {
    expect(() => removeMount(base(), "github-user")).toThrow(/owner/);
  });

  it("removeMount removes an unused mount", () => {
    const c = addMount(base(), "laptops", { type: "ssh" });
    expect(removeMount(c, "laptops").mounts.laptops).toBeUndefined();
  });

  it("renameMount moves the mount and every role on it", () => {
    let c = addMount(base(), "ci", GITHUB_ACTIONS_MOUNT);
    c = upsertRole(c, "deploy", {
      mount: "ci",
      bound_audiences: ["edgekms"],
      bound_claims: { repository: "acme/app" },
      policies: ["default-all"],
      token_ttl_secs: 600,
    });
    const next = renameMount(c, "ci", "actions");
    expect(next.mounts.ci).toBeUndefined();
    expect(next.mounts.actions).toEqual(GITHUB_ACTIONS_MOUNT);
    expect(next.roles.deploy?.mount).toBe("actions");
    expect(() => renameMount(next, "actions", "github-user")).toThrow(/already/);
  });
});

describe("roles", () => {
  it("upsertRole adds, replaces and renames", () => {
    const role = {
      mount: "github-user",
      github_user_ids: [2],
      policies: ["default-all"],
      token_ttl_secs: 600,
    };
    let c = upsertRole(base(), "reader", role);
    expect(c.roles.reader).toEqual(role);
    c = upsertRole(c, "reader", { ...role, token_ttl_secs: 900 });
    expect(c.roles.reader?.token_ttl_secs).toBe(900);
    c = upsertRole(c, "readers", role, "reader");
    expect(c.roles.reader).toBeUndefined();
    expect(c.roles.readers).toEqual(role);
  });

  it("upsertRole refuses to rename onto another role", () => {
    const c = upsertRole(base(), "reader", {
      mount: "github-user",
      github_user_ids: [2],
      policies: ["default-all"],
      token_ttl_secs: 600,
    });
    expect(() => upsertRole(c, "owner", c.roles.reader!, "reader")).toThrow(/already/);
  });

  it("removeRole removes it", () => {
    expect(removeRole(base(), "owner").roles.owner).toBeUndefined();
  });

  it("holdsAdmin is true for a role with a policy that has admin capabilities", () => {
    const c = upsertRole(base(), "reader", {
      mount: "github-user",
      github_user_ids: [2],
      policies: ["default-all"],
      token_ttl_secs: 600,
    });
    expect(holdsAdmin(c, "owner")).toBe(true);
    expect(holdsAdmin(c, "reader")).toBe(false);
  });

  it("cleanRole keeps only the fields the mount type takes, and drops empty optionals", () => {
    const messy = {
      mount: "laptops",
      bound_audiences: ["x"],
      bound_claims: { sub: "y" },
      ssh_keys: ["ssh-ed25519 AAAA"],
      github_user_ids: [3],
      policies: ["default-all"],
      token_ttl_secs: 600,
      not_before: 0,
    };
    expect(cleanRole(messy, "ssh")).toEqual({
      mount: "laptops",
      ssh_keys: ["ssh-ed25519 AAAA"],
      policies: ["default-all"],
      token_ttl_secs: 600,
    });
    expect(cleanRole(messy, "jwt")).toEqual({
      mount: "laptops",
      bound_audiences: ["x"],
      bound_claims: { sub: "y" },
      policies: ["default-all"],
      token_ttl_secs: 600,
    });
    expect(cleanRole({ ...messy, not_before: 5 }, "github-user")).toEqual({
      mount: "laptops",
      github_user_ids: [3],
      policies: ["default-all"],
      token_ttl_secs: 600,
      not_before: 5,
    });
  });
});

describe("policies", () => {
  it("the capability grid round-trips through setCapability", () => {
    let c = addKey(base(), "signing");
    c = addPolicy(c, "ci");
    expect(capabilityGrid(c, "ci")).toEqual({ default: new Set(), signing: new Set() });
    c = setCapability(c, "ci", "signing", "encrypt", true);
    c = setCapability(c, "ci", "signing", "read", true);
    c = setCapability(c, "ci", "default", "decrypt", true);
    expect(c.policies.ci?.keys).toEqual({ signing: ["encrypt", "read"], default: ["decrypt"] });
    const grid = capabilityGrid(c, "ci");
    expect(grid.signing).toEqual(new Set(["encrypt", "read"]));
    expect(grid.default).toEqual(new Set(["decrypt"]));
  });

  it("setCapability writes capabilities in a stable order and removes an emptied key", () => {
    let c = addPolicy(base(), "ci");
    c = setCapability(c, "ci", "default", "read", true);
    c = setCapability(c, "ci", "default", "encrypt", true);
    expect(c.policies.ci?.keys?.default).toEqual(["encrypt", "read"]);
    c = setCapability(c, "ci", "default", "encrypt", false);
    c = setCapability(c, "ci", "default", "read", false);
    expect(c.policies.ci).toEqual({});
  });

  it("setCapability does not change the input", () => {
    const c = base();
    setCapability(c, "default-all", "default", "read", false);
    expect(c.policies["default-all"]?.keys?.default).toContain("read");
  });

  it("setAdmin adds and removes admin capabilities, leaving admin out when none remain", () => {
    let c = setAdmin(base(), "admin", "token-revoke", false);
    expect(c.policies.admin).toEqual({ admin: ["token-create"] });
    c = setAdmin(c, "admin", "token-create", false);
    expect(c.policies.admin).toEqual({});
  });

  it("addPolicy refuses a duplicate; removePolicy refuses one a role uses", () => {
    expect(() => addPolicy(base(), "admin")).toThrow(/already/);
    expect(() => removePolicy(base(), "admin")).toThrow(/owner/);
    const c = addPolicy(base(), "spare");
    expect(removePolicy(c, "spare").policies.spare).toBeUndefined();
  });
});
