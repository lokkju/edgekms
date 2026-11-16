import { expect, test } from "./fixtures";

test("the allowlist shows logins looked up by id, or the id alone", async ({ page, state }) => {
  state.githubUsers.dana = 7;
  state.allowlist.allowlist.push({ github_id: 555_555, added_by: 1001, added_ms: 1_790_000_000_000 });
  await page.goto("/ops");
  const rows = page.getByTestId("allow-entry");
  await expect(rows.nth(0)).toContainText("dana");
  await expect(rows.nth(0)).toContainText("id 7");
  await expect(rows.nth(1)).toContainText("GitHub user");
  await expect(rows.nth(1)).toContainText("id 555555");
});

// ---- Invite requests (#54) ----

const NOV_10 = 1_762_732_800_000;
const NOV_11 = 1_762_819_200_000;

function pending(github_id: number, login: string, note: string, created_ms = NOV_11) {
  return {
    github_id,
    login,
    note,
    created_ms,
    status: "pending" as const,
    decided_by: null,
    decided_ms: null,
  };
}

test("pending invite requests show the note as text and the account's age", async ({
  page,
  state,
}) => {
  state.inviteRequests.requests = [
    pending(3001, "carol", "CI signing\n<b>for</b> a small project", NOV_10),
    pending(3002, "dave", ""),
  ];
  state.inviteRequests.pending = 2;
  state.githubProfiles[3001] = { login: "carol-renamed", created_at: "2015-03-01T00:00:00Z", public_repos: 12 };
  await page.goto("/ops");
  await expect(page.getByRole("heading", { name: "Invite requests (2 pending)" })).toBeVisible();
  const rows = page.getByTestId("invite-request");
  await expect(rows).toHaveCount(2);
  const carol = rows.nth(0);
  await expect(carol).toContainText("carol");
  await expect(carol).toContainText("id 3001");
  await expect(carol).toContainText("requested 2025-11-10");
  await expect(carol).toContainText("now @carol-renamed");
  await expect(carol).toContainText("account created 2015-03-01");
  await expect(carol).toContainText("days old");
  await expect(carol).toContainText("12 public repos");
  // The note is text: the markup shows as typed, and nothing is rendered from it.
  await expect(carol.getByTestId("invite-note")).toHaveText("CI signing\n<b>for</b> a small project");
  await expect(carol.locator("b")).toHaveCount(0);
  // A lookup GitHub can't answer leaves the row without those details.
  await expect(rows.nth(1)).not.toContainText("account created");
});

test("approving a request allowlists the user", async ({ page, state }) => {
  state.inviteRequests.requests = [pending(3011, "erin", "please")];
  state.inviteRequests.pending = 1;
  await page.goto("/ops");
  let asked = "";
  page.once("dialog", (d) => {
    asked = d.message();
    void d.accept();
  });
  await page.getByTestId("invite-request").getByRole("button", { name: "Approve" }).click();
  await expect(page.getByRole("status")).toContainText("erin can sign up now.");
  expect(asked).toContain("erin");
  await expect(page.getByTestId("invite-request")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Invite requests (0 pending)" })).toBeVisible();
  // The allowlist below reloaded with them on it.
  await expect(page.getByTestId("allow-entry").filter({ hasText: "id 3011" })).toHaveCount(1);
  expect(
    state.requests.some(
      (r) => r.method === "POST" && r.path === "/ops/invite-requests/3011/approve",
    ),
  ).toBe(true);
});

test("declining needs a confirmation", async ({ page, state }) => {
  state.inviteRequests.requests = [pending(3021, "frank", "")];
  state.inviteRequests.pending = 1;
  await page.goto("/ops");
  page.once("dialog", (d) => void d.dismiss());
  await page.getByTestId("invite-request").getByRole("button", { name: "Decline" }).click();
  await expect(page.getByTestId("invite-request")).toHaveCount(1);
  page.once("dialog", (d) => void d.accept());
  await page.getByTestId("invite-request").getByRole("button", { name: "Decline" }).click();
  await expect(page.getByTestId("invite-request")).toHaveCount(0);
  expect(state.inviteRequests.requests[0]?.status).toBe("declined");
});

test("decided requests show on request and can be deleted", async ({ page, state }) => {
  state.inviteRequests.requests = [
    { ...pending(3031, "gina", ""), status: "declined", decided_by: 1001, decided_ms: NOV_11 },
  ];
  await page.goto("/ops");
  await expect(page.getByTestId("decided-request")).toHaveCount(0);
  await page.getByRole("button", { name: "Show decided" }).click();
  const row = page.getByTestId("decided-request");
  await expect(row).toContainText("gina");
  await expect(row).toContainText("declined 2025-11-11 by id 1001");
  let asked = "";
  page.once("dialog", (d) => {
    asked = d.message();
    void d.accept();
  });
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByTestId("decided-request")).toHaveCount(0);
  expect(asked).toBe("Delete this request? A declined user can then request again.");
  expect(state.inviteRequests.requests).toEqual([]);
});

test("unverified requests are named apart and can be deleted", async ({ page, state }) => {
  state.inviteRequests.unverified = [3041];
  await page.goto("/ops");
  const notice = page.getByTestId("unverified-requests");
  await expect(notice).toContainText("3041");
  page.once("dialog", (d) => void d.accept());
  await notice.getByRole("button", { name: "Delete 3041" }).click();
  await expect(page.getByTestId("unverified-requests")).toHaveCount(0);
  expect(
    state.requests.some((r) => r.method === "DELETE" && r.path === "/ops/invite-requests/3041"),
  ).toBe(true);
});

test("at most 30 pending requests are looked up on GitHub", async ({ page, state }) => {
  state.inviteRequests.requests = Array.from({ length: 35 }, (_, i) =>
    pending(4000 + i, `user${i}`, "", NOV_11 + i),
  );
  state.inviteRequests.pending = 35;
  const looked: number[] = [];
  page.on("request", (r) => {
    const m = /api\.github\.com\/user\/(\d+)$/.exec(r.url());
    if (m) looked.push(Number(m[1]));
  });
  await page.goto("/ops");
  await expect(page.getByTestId("invite-request")).toHaveCount(35);
  await expect.poll(() => looked.filter((id) => id >= 4000).length).toBe(30);
  await page.waitForTimeout(200);
  expect(looked.filter((id) => id >= 4030)).toEqual([]);
});
