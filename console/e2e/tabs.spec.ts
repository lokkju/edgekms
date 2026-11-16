import { expect, test } from "./fixtures";

test("unsaved edits survive switching tabs, with no reload", async ({ page, state }) => {
  await page.goto("/t/acme/keys");
  await page.getByLabel("New key name").fill("infra-prod");
  await page.getByRole("button", { name: "Add key" }).click();
  await expect(page.getByTestId("key-row")).toHaveCount(2);

  await page.getByRole("link", { name: "Policies" }).click();
  await expect(page.getByLabel("default-all: decrypt on infra-prod")).toBeVisible();
  await page.getByRole("link", { name: "Keys" }).click();
  await expect(page.getByTestId("key-row")).toHaveCount(2);
  await expect(page.getByText("Unsaved changes")).toBeVisible();

  const loads = state.requests.filter((r) => r.method === "GET" && r.path === "/tenants/acme");
  expect(loads).toHaveLength(1);
});
