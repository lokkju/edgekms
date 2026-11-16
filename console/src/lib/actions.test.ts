import { describe, expect, it } from "vitest";
import { actionsClaims, isGithubActions, nameClaim, parseRepoSlug, tenantOrigin } from "./actions";
import { GITHUB_ACTIONS_MOUNT } from "./config";

describe("parseRepoSlug", () => {
  it("takes owner/repo", () => {
    expect(parseRepoSlug("acme/app")).toEqual({ owner: "acme", repo: "app" });
  });

  it("trims and accepts a github.com URL", () => {
    expect(parseRepoSlug("  https://github.com/acme/app.git ")).toEqual({ owner: "acme", repo: "app" });
    expect(parseRepoSlug("github.com/acme/app/")).toEqual({ owner: "acme", repo: "app" });
  });

  it("refuses anything else", () => {
    for (const s of ["", "acme", "acme/", "/app", "acme/app/extra", "acme/a b", "../x", "acme/.."]) {
      expect(parseRepoSlug(s), s).toBeNull();
    }
  });
});

describe("actionsClaims", () => {
  it("binds the ids, as the strings GitHub's token carries", () => {
    expect(actionsClaims({ repositoryId: 812345678, ownerId: 1234567 })).toEqual({
      repository_id: "812345678",
      repository_owner_id: "1234567",
    });
  });

  it("adds ref for a branch, and a glob when it has a *", () => {
    expect(actionsClaims({ repositoryId: 1, ownerId: 2, branch: "main" }).ref).toBe("refs/heads/main");
    expect(actionsClaims({ repositoryId: 1, ownerId: 2, branch: "release/*" }).ref).toEqual({
      glob: "refs/heads/release/*",
    });
  });

  it("keeps a full ref as given", () => {
    expect(actionsClaims({ repositoryId: 1, ownerId: 2, branch: "refs/tags/v*" }).ref).toEqual({
      glob: "refs/tags/v*",
    });
  });

  it("adds environment, and leaves out blanks", () => {
    const c = actionsClaims({ repositoryId: 1, ownerId: 2, branch: " ", environment: " prod " });
    expect(c).toEqual({ repository_id: "1", repository_owner_id: "2", environment: "prod" });
  });
});

describe("tenantOrigin", () => {
  it("swaps the console's app label for the tenant", () => {
    expect(tenantOrigin("https://app.edgekms.dev", "acme")).toBe("https://acme.edgekms.dev");
    expect(tenantOrigin("http://app.localhost:8787", "acme")).toBe("http://acme.localhost:8787");
  });

  it("is null off an app. host", () => {
    expect(tenantOrigin("http://127.0.0.1:4173", "acme")).toBeNull();
  });
});

describe("isGithubActions", () => {
  it("knows the preset by its issuer", () => {
    expect(isGithubActions(GITHUB_ACTIONS_MOUNT)).toBe(true);
    expect(isGithubActions({ type: "jwt", issuer: "https://accounts.google.com" })).toBe(false);
    expect(isGithubActions({ type: "ssh" })).toBe(false);
  });
});

describe("nameClaim", () => {
  it("flags the claims that hold a renameable name", () => {
    expect(nameClaim("repository")).toBe(true);
    expect(nameClaim(" repository_owner ")).toBe(true);
    expect(nameClaim("repository_id")).toBe(false);
    expect(nameClaim("ref")).toBe(false);
  });
});
