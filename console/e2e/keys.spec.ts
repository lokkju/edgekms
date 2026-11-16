import { expect, test } from "./fixtures";

test("rotate a key, then raise its minimum decryption version after a warning", async ({
  page,
  state,
}) => {
  await page.goto("/t/acme/keys");
  const row = page.locator('[data-testid="key-row"][data-key="default"]');
  // At versions 1 and 1 there's nothing to retire.
  await expect(row.getByRole("button", { name: "Raise minimum decryption version of default" })).toHaveCount(0);

  await row.getByRole("button", { name: "Rotate default" }).click();
  await row.getByRole("button", { name: "Rotate default" }).click();
  await expect(row.locator("td").nth(2)).toHaveText("3");

  await row.getByRole("button", { name: "Raise minimum decryption version of default" }).click();
  const form = page.getByTestId("raise-form");
  await expect(form).toContainText("stops decrypting");
  await expect(form.getByLabel("New minimum decryption version")).toHaveValue("3");
  await form.getByLabel("New minimum decryption version").fill("2");

  // Declining the confirmation changes nothing.
  page.once("dialog", (d) => void d.dismiss());
  await form.getByRole("button", { name: "Raise minimum" }).click();
  await expect(row.locator("td").nth(3)).toHaveText("1");

  let asked = "";
  page.once("dialog", (d) => {
    asked = d.message();
    void d.accept();
  });
  await form.getByRole("button", { name: "Raise minimum" }).click();
  await expect(row.locator("td").nth(3)).toHaveText("2");
  expect(asked).toContain("below 2 stops decrypting");
  await expect(page.getByTestId("raise-form")).toHaveCount(0);

  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  const put = state.requests.find((r) => r.method === "PUT" && r.path === "/tenants/acme/config");
  expect((put?.body as { keys: unknown }).keys).toEqual({
    default: { id: "k_00000000000000aa", latest_version: 3, min_decryption_version: 2 },
  });
});

test("a member sees no rotate controls", async ({ page, state }) => {
  state.me.tenants = [{ name: "acme", role: "member", status: "active" }];
  await page.goto("/t/acme/keys");
  await expect(page.getByTestId("key-row")).toHaveCount(1);
  await expect(page.getByRole("button", { name: /Rotate/ })).toHaveCount(0);
});
