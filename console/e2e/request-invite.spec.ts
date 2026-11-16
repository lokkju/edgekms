import { expect, test } from "./fixtures";

const NOV_11 = 1_762_819_200_000;

test("without a request session, the page offers a GitHub sign-in", async ({ page, state }) => {
  state.requester.session = null;
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-signin")).toContainText(
    "edgekms.dev is invite-only. Sign in with GitHub to request an invite.",
  );
  await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toHaveAttribute(
    "href",
    "/auth/login?return_to=%2F",
  );
  await expect(page.getByText("Already have access? You'll go straight to your tenants.")).toBeVisible();
  // The page is public: it never asks for the signed-in user, so it can't loop through GitHub.
  expect(state.requests.some((r) => r.path === "/me")).toBe(false);
  expect(state.logins).toEqual([]);
});

test("an expired request session is the same sign-in offer", async ({ page, state }) => {
  state.requester.session = "expired";
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-signin")).toBeVisible();
  expect(state.logins).toEqual([]);
});

test("a refused user files a request with a note", async ({ page, state }) => {
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-form")).toContainText("Signed in with GitHub as carol.");
  const note = page.getByLabel("What will you use edgekms for? (optional)");
  await note.fill("CI signing\nfor a small project");
  await expect(page.getByTestId("note-count")).toHaveText("30 / 500");
  await page.getByRole("button", { name: "Request an invite" }).click();
  await expect(page.getByTestId("invite-pending")).toContainText(
    "You asked for an invite on 2026-11-11. An operator will review it.",
  );
  await expect(page.getByTestId("invite-pending")).toContainText("edgekms doesn't email you");
  expect(state.requester.filed).toEqual(["CI signing\nfor a small project"]);
  const post = state.requests.find((r) => r.path === "/invite-requests");
  expect(post?.method).toBe("POST");
  expect(post?.headers["content-type"]).toBe("application/json");
});

test("an empty note is fine", async ({ page, state }) => {
  await page.goto("/request-invite");
  await page.getByRole("button", { name: "Request an invite" }).click();
  await expect(page.getByTestId("invite-pending")).toBeVisible();
  expect(state.requester.filed).toEqual([""]);
});

test("the page checks the note before sending it", async ({ page, state }) => {
  await page.goto("/request-invite");
  await page.getByLabel("What will you use edgekms for? (optional)").fill("x".repeat(501));
  await expect(page.getByTestId("note-count")).toHaveText("501 / 500");
  await expect(page.getByTestId("note-error")).toHaveText(
    "the note must be at most 500 characters",
  );
  await expect(page.getByRole("button", { name: "Request an invite" })).toBeDisabled();
  expect(state.requester.filed).toEqual([]);
});

test("the server's note refusal shows under the field", async ({ page, state }) => {
  state.requester.refuse = {
    status: 400,
    code: "note_invalid",
    message: "the note can't contain bidirectional formatting characters",
  };
  await page.goto("/request-invite");
  await page.getByLabel("What will you use edgekms for? (optional)").fill("fine");
  await page.getByRole("button", { name: "Request an invite" }).click();
  await expect(page.getByTestId("note-error")).toHaveText(
    "the note can't contain bidirectional formatting characters",
  );
});

test("a token that expires while typing keeps the note on screen", async ({ page, state }) => {
  await page.goto("/request-invite");
  const note = page.getByLabel("What will you use edgekms for? (optional)");
  await note.fill("my carefully written note");
  state.requester.session = "expired";
  await page.getByRole("button", { name: "Request an invite" }).click();
  await expect(page.getByTestId("invite-expired")).toHaveText(
    "Your sign-in for this request expired. Copy your note, then sign in again.",
  );
  await expect(note).toHaveValue("my carefully written note");
  await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
  expect(state.logins).toEqual([]);
});

for (const [status, code] of [
  [503, "invite_requests_full"],
  [403, "invite_requests_closed"],
] as const) {
  test(`${code} says to try again later`, async ({ page, state }) => {
    state.requester.refuse = { status, code, message: "refused" };
    await page.goto("/request-invite");
    await page.getByRole("button", { name: "Request an invite" }).click();
    await expect(page.getByRole("alert")).toHaveText(
      "We're not taking more requests right now. Try again later.",
    );
  });
}

test("already_admitted offers a sign-in", async ({ page, state }) => {
  state.requester.refuse = { status: 409, code: "already_admitted", message: "you can sign in now" };
  await page.goto("/request-invite");
  await page.getByRole("button", { name: "Request an invite" }).click();
  await expect(page.getByTestId("invite-admitted")).toContainText("You can sign in now");
  await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
});

test("not accepting shows no form", async ({ page, state }) => {
  state.requester.accepting = false;
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-closed")).toHaveText(
    "We're not taking invite requests right now.",
  );
  await expect(page.getByRole("button", { name: "Request an invite" })).toHaveCount(0);
});

test("a pending request shows its date", async ({ page, state }) => {
  state.requester.request = { status: "pending", created_ms: NOV_11, decided_ms: null };
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-pending")).toContainText("on 2025-11-11");
  await expect(page.getByRole("button", { name: "Request an invite" })).toHaveCount(0);
});

test("an approved request says to sign in", async ({ page, state }) => {
  state.requester.request = { status: "approved", created_ms: NOV_11, decided_ms: NOV_11 + 1 };
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-approved")).toContainText(
    "Your request was approved. Sign in to get started.",
  );
  await expect(page.getByRole("link", { name: "Sign in with GitHub" })).toBeVisible();
});

test("a declined request says so, and no second request can be filed", async ({ page, state }) => {
  state.requester.request = { status: "declined", created_ms: NOV_11, decided_ms: NOV_11 + 1 };
  await page.goto("/request-invite");
  await expect(page.getByTestId("invite-declined")).toHaveText(
    "Your request on 2025-11-11 wasn't approved.",
  );
  await expect(page.getByRole("button", { name: "Request an invite" })).toHaveCount(0);
});
