// Writes the user guide's screenshots to docs/images/console/. Run with `pnpm screenshots`
// (playwright.screenshots.config.ts); `pnpm e2e` doesn't pick up *.shot.ts files.
//
// The Roles shot follows the guide's GitHub Actions recipe click by click and checks that the
// config it saves is the one the guide prints, so the recipe and the screenshot can't drift.

import type { Page } from "@playwright/test";
import { expect, KEYS, SIGNATURE, sshKey, test } from "./fixtures";

const OUT = new URL("../../docs/images/console/", import.meta.url).pathname;

async function shot(page: Page, name: string, fullPage = false): Promise<void> {
  // Let fonts and layout settle; nothing animates, but a frame keeps the capture stable.
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))));
  await page.screenshot({ path: `${OUT}${name}.png`, fullPage, animations: "disabled" });
}

test("sign-in", async ({ page, state }) => {
  void state;
  await page.goto("/signin");
  await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
  await shot(page, "signin");
});

test("tenant list", async ({ page, state }) => {
  state.me.operator = false;
  state.me.tenants = [
    { name: "alice", role: "owner", status: "active" },
    { name: "acme", role: "owner", status: "active" },
    { name: "legacy", role: "member", status: "suspended" },
  ];
  state.me.invites = [{ name: "beta", role: "member" }];
  await page.goto("/");
  await expect(page.getByTestId("tenant")).toHaveCount(3);
  await shot(page, "tenants");
});

test("roles: the GitHub Actions recipe", async ({ page, state }) => {
  await page.goto("/t/acme/keys");
  await page.getByLabel("New key name").fill("infra-prod");
  await page.getByRole("button", { name: "Add key" }).click();
  await expect(page.getByTestId("key-row")).toHaveCount(2);

  await page.getByRole("link", { name: "Policies" }).click();
  await page.getByLabel("New policy name").fill("infra-prod-decrypt");
  await page.getByRole("button", { name: "Add policy" }).click();
  await page.getByLabel("infra-prod-decrypt: decrypt on infra-prod").check();

  await page.getByRole("link", { name: "Roles" }).click();
  await page.getByRole("button", { name: "Add mount" }).click();
  await page.getByLabel("Mount name").fill("actions");
  await expect(page.getByLabel("Type")).toHaveValue("actions");
  await page.getByRole("button", { name: "Add mount" }).click();

  const group = page.locator('[data-testid="role-group"][data-mount="actions"]');
  await group.getByRole("button", { name: "Add role" }).click();
  await group.getByLabel("Role name").fill("deploy-main");
  await group.getByLabel("Token lifetime (seconds)").fill("900");
  await group.getByLabel("infra-prod-decrypt").check();
  // On app.edgekms.dev the form starts with this audience; the local preview's origin has no
  // tenant to derive, so the shot types it.
  await group.getByLabel("Bound audiences, one per line").fill("https://acme.edgekms.dev");
  await group.getByLabel("Repository (owner/repo)").fill("acme/app");
  await group.getByLabel("Branch (optional)").fill("main");
  await group.getByRole("button", { name: "Look up repository" }).click();
  await expect(group.getByTestId("repo-found")).toContainText(
    "Found acme/app: repository id 812345678, owner acme id 1234567.",
  );
  await group.getByRole("button", { name: "Bind acme/app" }).click();
  await group.getByRole("button", { name: "Add role" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");

  const saved = state.tenants.acme?.config;
  expect(saved?.mounts.actions).toEqual({
    type: "jwt",
    issuer: "https://token.actions.githubusercontent.com",
    jwks_url: "https://token.actions.githubusercontent.com/.well-known/jwks",
  });
  expect(saved?.roles["deploy-main"]).toEqual({
    mount: "actions",
    bound_audiences: ["https://acme.edgekms.dev"],
    bound_claims: {
      repository_id: "812345678",
      repository_owner_id: "1234567",
      ref: "refs/heads/main",
    },
    policies: ["infra-prod-decrypt"],
    token_ttl_secs: 900,
  });
  expect(saved?.policies["infra-prod-decrypt"]).toEqual({ keys: { "infra-prod": ["decrypt"] } });

  // A fresh load of the saved config, without the "Saved." bar over the role.
  await page.goto("/t/acme/roles");
  await expect(page.locator('[data-testid="role"][data-role="deploy-main"]')).toBeVisible();
  await shot(page, "roles", true);
});

test("members", async ({ page, state }) => {
  const acme = state.tenants.acme;
  if (acme) acme.members = [
    { github_id: 1001, role: "owner" },
    { github_id: 3003, role: "member" },
  ];
  await page.goto("/t/acme/members");
  await page.getByLabel("GitHub login").fill("bob");
  await page.getByRole("button", { name: "Look up" }).click();
  await page.getByRole("button", { name: "Send invite" }).click();
  await expect(page.getByTestId("pending")).toContainText("bob");
  await shot(page, "members", true);
});

test("export, before confirming", async ({ page, state }) => {
  void state;
  await page.goto("/t/acme/export");
  await page.getByLabel("Type the tenant name to confirm").fill("acme");
  await expect(page.getByRole("button", { name: "Export root key" })).toBeEnabled();
  await expect(page.getByTestId("export-root-key")).toHaveCount(0);
  await shot(page, "export");
});

test("request an invite", async ({ page, state }) => {
  void state;
  await page.goto("/request-invite");
  await page
    .getByLabel("What will you use edgekms for? (optional)")
    .fill("Signing release artifacts in CI for a small open source project.");
  await expect(page.getByTestId("note-count")).toBeVisible();
  await shot(page, "request-invite");
});

test("ops", async ({ page, state }) => {
  state.inviteRequests = {
    requests: [
      {
        github_id: 3001,
        login: "carol",
        note: "Signing release artifacts in CI for a small open source project.",
        created_ms: 1_794_268_800_000,
        status: "pending",
        decided_by: null,
        decided_ms: null,
      },
      {
        github_id: 3002,
        login: "dave",
        note: "",
        created_ms: 1_794_355_200_000,
        status: "pending",
        decided_by: null,
        decided_ms: null,
      },
    ],
    unverified: [],
    pending: 2,
  };
  state.githubProfiles[3001] = {
    login: "carol",
    created_at: "2015-03-01T00:00:00Z",
    public_repos: 12,
  };
  state.githubUsers.dana = 7;
  await page.goto("/ops");
  await expect(page.getByTestId("invite-request")).toHaveCount(2);
  await expect(page.getByTestId("invite-request").first()).toContainText("public repos");
  await shot(page, "ops", true);
});

test("account: SSH keys, adding one", async ({ page, state }) => {
  state.fresh = true;
  state.sshKeys = {
    keys: [
      sshKey(KEYS.sk.line, { label: "yubikey-5c", last_used_ms: 1_794_398_400_000 }),
      sshKey(KEYS.ed25519.line, {
        label: "laptop",
        added_via: `ssh:${KEYS.sk.fingerprint}`,
        added_ms: 1_794_384_000_000,
      }),
    ],
    unverified: [],
  };
  await page.goto("/account");
  await expect(page.getByTestId("ssh-key")).toHaveCount(2);
  await page.getByLabel("Public key").fill(KEYS.ecdsa.line);
  await page.getByLabel("Label (optional)").fill("server break-glass");
  await expect(page.getByTestId("browser-fingerprint")).toContainText(KEYS.ecdsa.fingerprint);
  await page.getByRole("button", { name: "Get a signing command" }).click();
  await expect(page.getByTestId("signing-command")).toBeVisible();
  await page.getByLabel("Signature").fill(SIGNATURE);
  await shot(page, "account", true);
});
