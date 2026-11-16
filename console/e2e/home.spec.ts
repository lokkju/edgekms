import { expect, test } from "./fixtures";

test("lists tenants with role and status, and pending invites", async ({ page, state }) => {
  void state;
  await page.goto("/");
  const tenants = page.getByTestId("tenant");
  await expect(tenants).toHaveCount(2);
  await expect(tenants.nth(0)).toContainText("acme");
  await expect(tenants.nth(0)).toContainText("owner");
  await expect(tenants.nth(0)).toContainText("active");
  await expect(tenants.nth(1)).toContainText("frozen");
  await expect(tenants.nth(1)).toContainText("suspended");
  await expect(page.getByTestId("invite")).toContainText("beta");
  await expect(page.getByRole("link", { name: "Ops" })).toBeVisible();
});

test("accepting an invite moves it into the tenant list", async ({ page, state }) => {
  await page.goto("/");
  await page.getByTestId("invite").getByRole("button", { name: "Accept" }).click();
  await expect(page.getByTestId("invite")).toHaveCount(0);
  await expect(page.getByTestId("tenant")).toHaveCount(3);
  const accept = state.requests.find((r) => r.path === "/tenants/beta/accept");
  expect(accept?.method).toBe("POST");
  expect(accept?.headers["origin"]).toBeTruthy();
});

test("a non-operator sees no Ops link and gets the naming rule", async ({ page, state }) => {
  state.me.operator = false;
  await page.goto("/");
  await expect(page.getByTestId("tenant")).toHaveCount(2);
  await expect(page.getByRole("link", { name: "Ops" })).toHaveCount(0);
  await expect(page.getByText("must start with your GitHub login")).toBeVisible();
});

test("a tenant link opens the tenant without a page load", async ({ page, state }) => {
  void state;
  await page.goto("/");
  await page.getByTestId("tenant").first().click();
  await expect(page).toHaveURL(/\/t\/acme$/);
  await expect(page.getByTestId("key-row")).toHaveCount(1);
});
