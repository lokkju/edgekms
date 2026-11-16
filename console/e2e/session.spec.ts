import { expect, test } from "./fixtures";

test("25 minutes after sign-in, a banner warns the session ends in 5", async ({ page, state }) => {
  void state;
  await page.clock.install();
  await page.goto("/t/acme/keys?signed_in=1");
  await expect(page.getByTestId("key-row")).toHaveCount(1);
  await page.clock.runFor("24:50");
  await expect(page.getByTestId("session-expiry")).toHaveCount(0);
  await page.clock.runFor("00:20");
  await expect(page.getByTestId("session-expiry")).toContainText(
    "Your session ends in 5 minutes; save your changes.",
  );
  // It doesn't block: the page still works, and the banner can be dismissed.
  await page.getByRole("button", { name: "Rotate default" }).click();
  await page.getByTestId("session-expiry").getByRole("button", { name: "Dismiss" }).click();
  await expect(page.getByTestId("session-expiry")).toHaveCount(0);
});

test("without a sign-in mark the session start is unknown, so no warning", async ({
  page,
  state,
}) => {
  void state;
  await page.clock.install();
  await page.goto("/t/acme/keys");
  await expect(page.getByTestId("key-row")).toHaveCount(1);
  await page.clock.runFor("29:00");
  await expect(page.getByTestId("session-expiry")).toHaveCount(0);
});

test("an auth_failed reply sends the user to sign in with the current path", async ({
  page,
  state,
}) => {
  state.session = "auth_failed";
  await page.goto("/t/acme/roles");
  await expect.poll(() => state.logins).toContain("?return_to=%2Ft%2Facme%2Froles");
  // The fake sign-in sends the browser back where it was, now signed in, and the SPA takes the
  // sign-in mark out of the address.
  await expect(page).toHaveURL(/\/t\/acme\/roles$/);
  await expect(page.getByTestId("role")).toHaveCount(1);
});

test("a session refused right after sign-in stops instead of looping through GitHub", async ({
  page,
  state,
}) => {
  state.session = "auth_failed";
  state.loginFixes = false;
  await page.goto("/t/acme/roles");
  await expect(page).toHaveURL(/\/signin\?error=login_failed$/);
  expect(state.logins).toHaveLength(1);
});

test("a no_session reply sends the user to sign in", async ({ page, state }) => {
  state.session = "no_session";
  await page.goto("/");
  await expect.poll(() => state.logins).toContain("?return_to=%2F");
});

test("a plain 403 says permission, not sign in", async ({ page, state }) => {
  await page.route("**/api/v1/tenants/acme", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ errors: ["permission denied"] }),
    }),
  );
  await page.goto("/t/acme");
  await expect(page.getByText("You don't have permission to see this tenant.")).toBeVisible();
  expect(state.logins).toEqual([]);
});

test("signing out leaves for the sign-in page", async ({ page, state }) => {
  void state;
  await page.goto("/");
  page.once("dialog", (d) => void d.accept());
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/signin$/);
});

test("a failed sign-out says the sessions are still active and stays put", async ({
  page,
  state,
}) => {
  state.logoutStatus = 500;
  await page.goto("/");
  page.once("dialog", (d) => void d.accept());
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByText("Sign-out didn't complete; your sessions are still active. Try again."),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("login")).toHaveText("alice");
});
