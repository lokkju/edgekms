import { expect, test } from "./fixtures";

test("invite by GitHub login resolves the id and sends it", async ({ page, state }) => {
  await page.goto("/t/acme/members");
  await expect(page.getByTestId("member")).toContainText("alice (you)");

  await page.getByLabel("GitHub login").fill("bob");
  await page.getByRole("button", { name: "Look up" }).click();
  await expect(page.getByTestId("invite-confirm")).toContainText("bob");
  await expect(page.getByTestId("invite-confirm")).toContainText("4242");
  await page.getByRole("button", { name: "Send invite" }).click();

  await expect(page.getByTestId("pending")).toContainText("bob");
  await expect(page.getByTestId("pending")).toContainText("id 4242");
  const put = state.requests.find((r) => r.method === "PUT" && r.path === "/tenants/acme/members/4242");
  expect(put?.body).toEqual({ role: "member" });
});

test("members and invites show logins looked up by id, or the id alone", async ({
  page,
  state,
}) => {
  state.tenants.acme!.members.push({ github_id: 4242, role: "member" });
  state.tenants.acme!.invites = [{ github_id: 999_999, role: "owner" }];
  await page.goto("/t/acme/members");
  await expect(page.getByTestId("member").nth(1)).toContainText("bob");
  await expect(page.getByTestId("member").nth(1)).toContainText("id 4242");
  // GitHub knows no account 999999: the row keeps the id.
  await expect(page.getByTestId("pending")).toContainText("GitHub user");
  await expect(page.getByTestId("pending")).toContainText("id 999999");
});

test("an unknown login says so and sends nothing", async ({ page, state }) => {
  await page.goto("/t/acme/members");
  await page.getByLabel("GitHub login").fill("nobody-at-all");
  await page.getByRole("button", { name: "Look up" }).click();
  await expect(page.getByRole("alert")).toContainText("No GitHub account named nobody-at-all");
  expect(state.requests.filter((r) => r.path.includes("/members/"))).toEqual([]);
});

test("withdrawing an invite asks first", async ({ page, state }) => {
  state.tenants.acme!.invites = [{ github_id: 4242, role: "member" }];
  await page.goto("/t/acme/members");
  page.once("dialog", (d) => void d.accept());
  await page.getByRole("button", { name: "Withdraw" }).click();
  await expect(page.getByTestId("pending")).toHaveCount(0);
  expect(state.requests.some((r) => r.method === "DELETE" && r.path === "/tenants/acme/members/4242")).toBe(true);
});
