import type { Page } from "@playwright/test";
import { expect, KEYS, SIGNATURE, sshKey, test } from "./fixtures";

const ed = sshKey(KEYS.ed25519.line, { label: "laptop", last_used_ms: 1_794_400_000_000 });
const ec = sshKey(KEYS.ecdsa.line, { added_via: `ssh:${KEYS.ed25519.fingerprint}` });
const sk = sshKey(KEYS.sk.line, { label: "yubikey-5c", added_via: `ssh:${KEYS.ed25519.fingerprint}` });

const row = (page: Page, fp: string) => page.locator(`[data-testid="ssh-key"][data-fingerprint="${fp}"]`);

/**
 * Whether the page lays out at the screen's width. A phone widens its layout viewport to fit
 * anything that overflows the document, so `innerWidth` grows past `screen.width` when it does.
 */
const fitsScreen = (page: Page) =>
  page.evaluate(() => innerWidth <= screen.width && document.documentElement.scrollWidth <= innerWidth);

async function getCommand(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Get a signing command" }).click();
  await expect(page.getByTestId("signing-command")).toBeVisible();
}

test("the header links to the Account page, which lists keys and where they came from", async ({
  page,
  state,
}) => {
  state.sshKeys = { keys: [ed, ec, sk], unverified: [] };
  await page.goto("/");
  await page.getByRole("link", { name: "Account" }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "SSH keys" })).toBeVisible();
  await expect(page.getByTestId("ssh-key")).toHaveCount(3);

  const edRow = row(page, ed.fingerprint);
  await expect(edRow).toContainText("laptop");
  await expect(edRow.getByTestId("fingerprint")).toHaveText(KEYS.ed25519.fingerprint);
  await expect(edRow.getByTestId("lineage")).toHaveText("added from a GitHub login");
  await expect(edRow).toContainText("2026-11-11");
  await expect(edRow.getByTestId("no-touch")).toHaveText("no touch required");

  await expect(row(page, ec.fingerprint).getByTestId("lineage")).toHaveText("added from SSH key laptop");
  await expect(row(page, ec.fingerprint)).toContainText("no label");
  await expect(row(page, ec.fingerprint)).toContainText("never");

  // A security key needs a touch for every signature, so it isn't marked.
  await expect(row(page, sk.fingerprint).getByTestId("no-touch")).toHaveCount(0);
  await expect(page.getByTestId("touch-advice")).toContainText("ssh-add -c");
  await expect(page.getByTestId("unverified-keys")).toHaveCount(0);
  // The table scrolls inside its card; the page stays the screen's width.
  expect(await fitsScreen(page)).toBe(true);
});

test("a row that fails its integrity check shows apart and can be deleted", async ({ page, state }) => {
  state.sshKeys = { keys: [sk], unverified: [KEYS.ecdsa.fingerprint] };
  await page.goto("/account");
  const box = page.getByTestId("unverified-keys");
  await expect(box).toContainText("This key's record failed its integrity check and can't log in.");
  await expect(box).toContainText(KEYS.ecdsa.fingerprint);
  await expect(page.getByTestId("touch-advice")).toHaveCount(0);

  page.once("dialog", (d) => void d.accept());
  await box.getByRole("button", { name: `Delete ${KEYS.ecdsa.fingerprint}` }).click();
  await expect(page.getByTestId("unverified-keys")).toHaveCount(0);
  const deletes = state.requests.filter((r) => r.method === "DELETE");
  expect(deletes.map((r) => r.path)).toEqual([`/me/ssh-keys/${ec.id}`]);
});

test("adding a key: paste, get a signing command, paste the signature", async ({ page, state }) => {
  state.fresh = true;
  await page.goto("/account");
  await expect(page.getByText("No SSH keys yet.")).toBeVisible();

  await page.getByLabel("Public key").fill(KEYS.ed25519.line);
  // The fingerprint the browser computes is the one ssh-keygen -lf prints.
  await expect(page.getByTestId("browser-fingerprint")).toContainText(KEYS.ed25519.fingerprint);
  // The label starts as the key's comment.
  await expect(page.getByLabel("Label (optional)")).toHaveValue("nick@laptop");
  await page.getByLabel("Label (optional)").fill("work laptop");

  await getCommand(page);
  const challenge = state.sshChallenges[0] as string;
  // The account the key goes to leads the command, and is in what's signed.
  expect(challenge.startsWith("ekmsr.1001.alice.")).toBe(true);
  await expect(page.getByTestId("signing-command")).toHaveText(
    `printf '%s\\n' 'Registering this key to GitHub account alice (1001)' >&2; ` +
      `printf '%s' '${challenge}' | ssh-keygen -Y sign -n edgekms-register -f ~/.ssh/YOUR_KEY.pub`,
  );
  await expect(page.getByTestId("register-account")).toHaveText(
    "This registers the key to your GitHub account alice (1001).",
  );
  await expect(page.getByTestId("countdown")).toHaveText(/^Expires in [45]:\d\d$/);
  await expect(page.getByText("edgekms account ssh-keys add")).toBeVisible();
  // The long command doesn't make the page wider than the screen.
  expect(await fitsScreen(page)).toBe(true);

  await page.getByLabel("Signature").fill(SIGNATURE);
  await page.getByRole("button", { name: "Add key" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Added work laptop to GitHub account alice (1001).",
  );
  await expect(row(page, KEYS.ed25519.fingerprint)).toContainText("work laptop");
  await expect(page.getByLabel("Public key")).toHaveValue("");

  const post = state.requests.find((r) => r.method === "POST" && r.path === "/me/ssh-keys");
  expect(post?.body).toEqual({
    public_key: KEYS.ed25519.line,
    label: "work laptop",
    challenge,
    signature: SIGNATURE + "\n",
  });
  // Nothing about the add stays in browser storage.
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).toBe("{}");
});

test("a challenge naming another account is never shown as a command to run", async ({ page, state }) => {
  state.fresh = true;
  state.sshChallengeAccount = { github_id: 666, login: "mallory" };
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.ed25519.line);
  await page.getByRole("button", { name: "Get a signing command" }).click();
  await expect(page.getByTestId("add-error")).toHaveText(
    "The control plane's challenge would register the key to GitHub account mallory (666), not to you (alice, 1001). Don't sign it; reload the page and try again.",
  );
  await expect(page.getByTestId("signing-command")).toHaveCount(0);
  await expect(page.getByLabel("Signature")).toBeDisabled();
});

test("the page refuses what it can tell is wrong before asking for a command", async ({ page, state }) => {
  state.fresh = true;
  await page.goto("/account");
  const button = page.getByRole("button", { name: "Get a signing command" });
  await expect(button).toBeDisabled();
  await page.getByLabel("Public key").fill("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCg rsa");
  await expect(page.getByTestId("key-problem")).toContainText("RSA and other types can't log in.");
  await expect(button).toBeDisabled();
  await page.getByLabel("Public key").fill("not a key");
  await expect(page.getByTestId("key-problem")).toContainText("isn't an OpenSSH public key line");
  await page.getByLabel("Public key").fill(KEYS.sk.line);
  await expect(button).toBeEnabled();
  await page.getByLabel("Label (optional)").fill("x".repeat(65));
  await expect(page.getByTestId("label-problem")).toHaveText("the label must be at most 64 characters");
  await expect(button).toBeDisabled();
  expect(state.sshChallenges).toEqual([]);
});

const REFUSALS: [number, string, string][] = [
  [400, "ssh_key_proof_failed", "The signature didn't match this key and challenge: get a new signing command and try again."],
  [409, "ssh_key_in_use", "That key is already registered to an edgekms account, this one or another."],
  [409, "ssh_key_limit", "Your account has 10 SSH keys, the most it can hold; remove one to add another."],
  [400, "label_invalid", "The label must be at most 64 characters"],
  [400, "ssh_key_invalid", "That isn't an OpenSSH public key line"],
  [400, "ssh_key_unsupported", "RSA and other types can't log in."],
];

test("each refusal of the add gets its own sentence", async ({ page, state }) => {
  state.fresh = true;
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.ecdsa.line);
  for (const [status, code, sentence] of REFUSALS) {
    if ((await page.getByTestId("signing-command").count()) === 0) await getCommand(page);
    state.sshAddRefuse = { status, code, message: code.replace(/_/g, " ") };
    await page.getByLabel("Signature").fill(SIGNATURE);
    await page.getByRole("button", { name: "Add key" }).click();
    await expect(page.getByTestId("add-error"), code).toContainText(sentence);
  }
  expect(state.sshKeys.keys).toEqual([]);
});

test("a failed proof asks for a new command", async ({ page, state }) => {
  state.fresh = true;
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.ecdsa.line);
  await getCommand(page);
  state.sshAddRefuse = { status: 400, code: "ssh_key_proof_failed", message: "ssh key proof failed" };
  await page.getByLabel("Signature").fill(SIGNATURE);
  await page.getByRole("button", { name: "Add key" }).click();
  await expect(page.getByTestId("add-error")).toContainText("get a new signing command");
  await expect(page.getByTestId("signing-command")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Add key" })).toBeDisabled();
});

test("a stale login detours through sign-in and comes back with the key and label", async ({
  page,
  state,
}) => {
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.ed25519.line);
  await page.getByLabel("Label (optional)").fill("break-glass");
  await page.getByRole("button", { name: "Get a signing command" }).click();

  await expect.poll(() => state.logins).toEqual(["?return_to=%2Faccount"]);
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByLabel("Public key")).toHaveValue(KEYS.ed25519.line);
  await expect(page.getByLabel("Label (optional)")).toHaveValue("break-glass");
  await expect(page.getByRole("status")).toContainText("You're signed in again");
  // The draft is read once, then gone.
  expect(await page.evaluate(() => JSON.stringify({ ...sessionStorage }))).toBe("{}");

  await getCommand(page);
  expect(state.sshChallenges).toHaveLength(1);
});

test("a login that went stale before Add key also detours", async ({ page, state }) => {
  state.fresh = true;
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.sk.line);
  await getCommand(page);
  state.fresh = false;
  await page.getByLabel("Signature").fill(SIGNATURE);
  await page.getByRole("button", { name: "Add key" }).click();
  await expect.poll(() => state.logins).toEqual(["?return_to=%2Faccount"]);
  await expect(page.getByLabel("Public key")).toHaveValue(KEYS.sk.line);
  await expect(page.getByLabel("Label (optional)")).toHaveValue("yubikey-5c");
  // The signature isn't kept: it goes with a challenge that's gone.
  await expect(page.getByLabel("Signature")).toHaveValue("");
});

test("removing a key offers the keys it added, checked, and deletes each checked one", async ({
  page,
  state,
}) => {
  const other = sshKey(KEYS.sk.line.replace("AAAAIAMK", "AAAAIAML"), { label: "spare" });
  state.sshKeys = { keys: [ed, ec, sk, other], unverified: [] };
  await page.goto("/account");
  await row(page, ed.fingerprint).getByRole("button", { name: "Delete laptop" }).click();

  const confirm = page.getByTestId("remove-confirm");
  await expect(confirm).toContainText("laptop");
  await expect(confirm).toContainText(KEYS.ed25519.fingerprint);
  await expect(confirm.getByRole("group", { name: "Also remove keys this key added" })).toBeVisible();
  const children = confirm.getByRole("checkbox");
  await expect(children).toHaveCount(2);
  await expect(children.nth(0)).toBeChecked();
  await expect(children.nth(1)).toBeChecked();
  await expect(confirm).not.toContainText("spare");

  // Keep the security key.
  await confirm.getByRole("checkbox", { name: /yubikey-5c/ }).uncheck();
  await confirm.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByTestId("ssh-key")).toHaveCount(2);

  const deletes = state.requests.filter((r) => r.method === "DELETE").map((r) => r.path);
  expect(deletes).toEqual([`/me/ssh-keys/${ed.id}`, `/me/ssh-keys/${ec.id}`]);
  expect(state.sshKeys.keys.map((k) => k.label)).toEqual(["yubikey-5c", "spare"]);
});

test("removing a key that added none asks once, and Cancel removes nothing", async ({ page, state }) => {
  state.sshKeys = { keys: [sk], unverified: [] };
  await page.goto("/account");
  await page.getByRole("button", { name: "Delete yubikey-5c" }).click();
  const confirm = page.getByTestId("remove-confirm");
  await expect(confirm.getByRole("checkbox")).toHaveCount(0);
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(confirm).toHaveCount(0);
  await page.getByRole("button", { name: "Delete yubikey-5c" }).click();
  await page.getByTestId("remove-confirm").getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText("No SSH keys yet.")).toBeVisible();
  expect(state.requests.filter((r) => r.method === "DELETE").map((r) => r.path)).toEqual([
    `/me/ssh-keys/${sk.id}`,
  ]);
});
