import { SIGNIN_MESSAGES } from "../src/lib/signin";
import { expect, test } from "./fixtures";

test("the sign-in page has one GitHub button and no error by default", async ({ page, state }) => {
  void state;
  await page.goto("/signin");
  const button = page.getByRole("link", { name: "Sign in with GitHub" });
  await expect(button).toHaveAttribute("href", "/auth/login?return_to=%2F");
  await expect(page.getByTestId("signin-error")).toHaveCount(0);
});

for (const [code, message] of Object.entries(SIGNIN_MESSAGES)) {
  test(`?error=${code} shows its message`, async ({ page, state }) => {
    void state;
    await page.goto(`/signin?error=${code}`);
    await expect(page.getByTestId("signin-error")).toHaveText(message);
  });
}

test("signup_closed tells an invitee what to do", async ({ page, state }) => {
  void state;
  await page.goto("/signin?error=signup_closed");
  await expect(page.getByTestId("signin-error")).toContainText("isn't taking new signups");
  await expect(page.getByTestId("signin-error")).toContainText("after they send the invite");
});

test("an unknown code gets a generic message", async ({ page, state }) => {
  void state;
  await page.goto("/signin?error=whatever");
  await expect(page.getByTestId("signin-error")).toHaveText("Sign-in failed. Try again.");
});
