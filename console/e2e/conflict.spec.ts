import { expect, test } from "./fixtures";

test("a 409 keeps the user's edits visible and shows the newer config", async ({ page, state }) => {
  state.conflictNext = true;
  await page.goto("/t/acme/keys");
  await page.getByLabel("New key name").fill("signing");
  await page.getByRole("button", { name: "Add key" }).click();
  await page.getByRole("button", { name: "Save" }).click();

  const conflict = page.getByTestId("conflict");
  await expect(conflict).toContainText("This config changed elsewhere.");
  // The user's version, with their new key, stays on screen.
  await expect(page.getByTestId("conflict-copy")).toContainText('"signing"');
  // The editor shows the version someone else saved, not a silent overwrite.
  const rows = page.getByTestId("key-row");
  await expect(rows).toHaveCount(2);
  await expect(rows.filter({ hasText: "other" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "signing" })).toHaveCount(0);
  expect(state.tenants.acme?.config_version).toBe(4);
  expect(Object.keys(state.tenants.acme?.config.keys ?? {})).not.toContain("signing");

  // Loading their version back and saving is a deliberate overwrite at the new version.
  await page.getByRole("button", { name: "Load my version into the editor" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  const puts = state.requests.filter((r) => r.method === "PUT");
  expect(puts.at(-1)?.headers["if-match"]).toBe('"4"');
});
