import { expect, test } from "./fixtures";

test("export needs a fresh login, then shows the key once", async ({ page, state }) => {
  await page.goto("/t/acme/export");
  const button = page.getByRole("button", { name: "Export root key" });
  await expect(button).toBeDisabled();
  await page.getByLabel("Type the tenant name to confirm").fill("ACME");
  await expect(button).toBeDisabled();
  await page.getByLabel("Type the tenant name to confirm").fill("acme");
  await button.click();

  // Stale login: off to sign in, and back to the export tab.
  await expect.poll(() => state.logins).toContain("?return_to=%2Ft%2Facme%2Fexport");
  await expect(page).toHaveURL(/\/t\/acme\/export$/);

  await page.getByLabel("Type the tenant name to confirm").fill("acme");
  await page.getByRole("button", { name: "Export root key" }).click();
  await expect(page.getByTestId("export-root-id")).toHaveText("r_acme");
  await expect(page.getByTestId("export-root-key")).toHaveText(
    "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=",
  );

  // Leaving the view drops it; coming back shows the confirmation again.
  await page.getByRole("link", { name: "Keys" }).click();
  await page.getByRole("link", { name: "Export" }).click();
  await expect(page.getByTestId("export-root-key")).toHaveCount(0);
  await expect(page.getByLabel("Type the tenant name to confirm")).toHaveValue("");
  await expect(page.getByText("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQ")).toHaveCount(0);

  // Nothing about it lands in browser storage.
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).toBe("{}");
});

test("Download config saves the tenant's config, with no root key", async ({ page, state }) => {
  await page.goto("/t/acme/export");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download config" }).click(),
  ]);
  expect(download.suggestedFilename()).toBe("acme-config.json");
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  expect(JSON.parse(text)).toEqual(state.tenants.acme?.config);
  expect(text).not.toContain("root_key");
  // Built in the browser: no request went out for it.
  expect(state.requests.filter((r) => r.method !== "GET")).toEqual([]);
});

test("a member has no Export tab", async ({ page, state }) => {
  state.me.tenants = [{ name: "acme", role: "member", status: "active" }];
  await page.goto("/t/acme");
  await expect(page.getByRole("link", { name: "Members" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Export" })).toHaveCount(0);
});
