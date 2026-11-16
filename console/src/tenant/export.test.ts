import { describe, expect, it } from "vitest";
import { configFile, confirmMatches, exportReturnPath } from "./export";

describe("confirmMatches", () => {
  it("is true only for the exact tenant name", () => {
    expect(confirmMatches("acme-prod", "acme-prod")).toBe(true);
  });

  it("is case-sensitive", () => {
    expect(confirmMatches("Acme-Prod", "acme-prod")).toBe(false);
  });

  it("does not trim or accept partial input", () => {
    expect(confirmMatches(" acme-prod", "acme-prod")).toBe(false);
    expect(confirmMatches("acme-prod ", "acme-prod")).toBe(false);
    expect(confirmMatches("acme", "acme-prod")).toBe(false);
    expect(confirmMatches("", "")).toBe(false);
  });
});

describe("configFile", () => {
  const config = {
    root_id: "r_acme",
    keys: { default: { id: "k_00000000000000aa", latest_version: 2, min_decryption_version: 1 } },
    mounts: {},
    roles: {},
    policies: {},
  };

  it("names the file after the tenant", () => {
    expect(configFile("acme", config).filename).toBe("acme-config.json");
  });

  it("is the config as indented JSON, ending in a newline", () => {
    const { text } = configFile("acme", config);
    expect(text.endsWith("}\n")).toBe(true);
    expect(JSON.parse(text)).toEqual(config);
    expect(text).toContain('\n  "keys": {');
  });

  it("holds the root id and key ids, and nothing else", () => {
    const { text } = configFile("acme", config);
    expect(text).toContain("r_acme");
    expect(text).toContain("k_00000000000000aa");
    expect(text).not.toContain("root_key");
  });
});

describe("exportReturnPath", () => {
  it("is the tenant's export tab, encoded", () => {
    expect(exportReturnPath("acme")).toBe("/t/acme/export");
    expect(exportReturnPath("a b")).toBe("/t/a%20b/export");
  });
});
