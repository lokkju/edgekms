import { expect, test } from "./fixtures";

const SSH_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ3m8Uf1qkqYbW5j8Yw9oKk2Yh8sZy0M3oQh1x2v3w4 ops@laptop";

test("add an ssh mount and a role, then save with If-Match", async ({ page, state }) => {
  await page.goto("/t/acme/roles");

  await page.getByRole("button", { name: "Add mount" }).click();
  await page.getByLabel("Mount name").fill("laptops");
  await page.getByLabel("Type").selectOption("ssh");
  await page.getByRole("button", { name: "Add mount" }).click();
  await expect(page.locator('[data-testid="mount"][data-mount="laptops"]')).toBeVisible();

  const group = page.locator('[data-testid="role-group"][data-mount="laptops"]');
  await group.getByRole("button", { name: "Add role" }).click();
  await group.getByLabel("Role name").fill("ops");
  await group.getByLabel("Token lifetime (seconds)").fill("900");
  await group.getByLabel("default-all").check();
  await group.getByLabel("SSH public keys, one per line").fill(SSH_KEY);
  await group.getByRole("button", { name: "Add role" }).click();
  await expect(group.locator('[data-testid="role"][data-role="ops"]')).toBeVisible();

  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");

  const put = state.requests.find((r) => r.method === "PUT" && r.path === "/tenants/acme/config");
  expect(put?.headers["if-match"]).toBe('"3"');
  expect(put?.headers["content-type"]).toBe("application/json");
  expect(put?.body).toEqual({
    root_id: "r_acme",
    keys: { default: { id: "k_00000000000000aa", latest_version: 1, min_decryption_version: 1 } },
    mounts: {
      "github-user": { type: "github-user", client_id: "Iv23liEdgekms" },
      laptops: { type: "ssh" },
    },
    roles: {
      owner: {
        mount: "github-user",
        github_user_ids: [1001],
        policies: ["admin", "default-all"],
        token_ttl_secs: 3600,
      },
      ops: { mount: "laptops", ssh_keys: [SSH_KEY], policies: ["default-all"], token_ttl_secs: 900 },
    },
    policies: {
      admin: { admin: ["token-create", "token-revoke"] },
      "default-all": { keys: { default: ["encrypt", "decrypt", "rewrap", "read"] } },
    },
  });
  expect(state.tenants.acme?.config_version).toBe(4);
});

test("a GitHub Actions mount uses the preset and a jwt role takes claims", async ({
  page,
  state,
}) => {
  await page.goto("/t/acme/roles");
  await page.getByRole("button", { name: "Add mount" }).click();
  await page.getByLabel("Mount name").fill("actions");
  await page.getByRole("button", { name: "Add mount" }).click();

  const group = page.locator('[data-testid="role-group"][data-mount="actions"]');
  await group.getByRole("button", { name: "Add role" }).click();
  await group.getByLabel("Role name").fill("deploy");
  await group.getByLabel("default-all").check();
  await group.getByLabel("Bound audiences, one per line").fill("https://github.com/acme");
  await group.getByRole("button", { name: "Add claim" }).click();
  await group.getByLabel("Claim name").fill("repository");
  await group.getByLabel("Claim value").fill("acme/app");
  await expect(group.getByTestId("name-claim")).toHaveText("repository can be renamed; prefer ids.");
  await group.getByRole("button", { name: "Add claim" }).click();
  await group.getByLabel("Claim name").nth(1).fill("ref");
  await group.getByLabel("Match").nth(1).selectOption("glob");
  await group.getByLabel("Claim value").nth(1).fill("refs/tags/*");
  await group.getByRole("button", { name: "Add role" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");

  const body = state.requests.find((r) => r.method === "PUT")?.body as {
    mounts: Record<string, unknown>;
    roles: Record<string, unknown>;
  };
  expect(body.mounts.actions).toEqual({
    type: "jwt",
    issuer: "https://token.actions.githubusercontent.com",
    jwks_url: "https://token.actions.githubusercontent.com/.well-known/jwks",
  });
  expect(body.roles.deploy).toEqual({
    mount: "actions",
    bound_audiences: ["https://github.com/acme"],
    bound_claims: { repository: "acme/app", ref: { glob: "refs/tags/*" } },
    policies: ["default-all"],
    token_ttl_secs: 3600,
  });
});

test("the GitHub Actions preset binds a repository by id, for the tenant's audience", async ({
  page,
  state,
}) => {
  // On an app. host, as in production, so the tenant's origin can be derived.
  await page.goto("http://app.localhost:4173/t/acme/roles");
  await page.getByRole("button", { name: "Add mount" }).click();
  await page.getByLabel("Mount name").fill("actions");
  await page.getByRole("button", { name: "Add mount" }).click();

  const group = page.locator('[data-testid="role-group"][data-mount="actions"]');
  await group.getByRole("button", { name: "Add role" }).click();
  await expect(group.getByLabel("Bound audiences, one per line")).toHaveValue(
    "http://acme.localhost:4173",
  );
  await group.getByLabel("Role name").fill("deploy-main");
  await group.getByLabel("default-all").check();

  await group.getByLabel("Repository (owner/repo)").fill("acme/missing");
  await group.getByRole("button", { name: "Look up repository" }).click();
  await expect(group.getByRole("alert")).toHaveText("No public GitHub repository acme/missing.");

  await group.getByLabel("Repository (owner/repo)").fill("Acme/App");
  await group.getByLabel("Branch (optional)").fill("main");
  await group.getByRole("button", { name: "Look up repository" }).click();
  await expect(group.getByTestId("repo-found")).toContainText(
    "Found acme/app: repository id 812345678, owner acme id 1234567.",
  );
  await group.getByRole("button", { name: "Bind acme/app" }).click();
  await expect(group.getByLabel("Claim name")).toHaveCount(3);
  await expect(group.getByTestId("name-claim")).toHaveCount(0);

  await group.getByRole("button", { name: "Add role" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");

  const body = state.requests.find((r) => r.method === "PUT")?.body as {
    roles: Record<string, unknown>;
  };
  expect(body.roles["deploy-main"]).toEqual({
    mount: "actions",
    bound_audiences: ["http://acme.localhost:4173"],
    bound_claims: {
      repository_id: "812345678",
      repository_owner_id: "1234567",
      ref: "refs/heads/main",
    },
    policies: ["default-all"],
    token_ttl_secs: 3600,
  });
});

test("a 400 shows the server's message at the top of the editor", async ({ page, state }) => {
  void state;
  await page.route("**/api/v1/tenants/acme/config", (route) =>
    route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({ errors: ["invalid config: roles.ops: an SSH role needs ssh_keys"] }),
    }),
  );
  await page.goto("/t/acme/keys");
  await page.getByLabel("New key name").fill("signing");
  await page.getByRole("button", { name: "Add key" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByTestId("save-error")).toHaveText(
    "invalid config: roles.ops: an SSH role needs ssh_keys",
  );
});
