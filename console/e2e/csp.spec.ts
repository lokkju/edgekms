import type { Page } from "@playwright/test";
import { CSP } from "../vite.config";
import { expect, KEYS, sshKey, test } from "./fixtures";

const PAGES = [
  "/signin",
  "/signin?error=state",
  "/",
  "/t/acme/keys",
  "/t/acme/roles",
  "/t/acme/policies",
  "/t/acme/raw",
  "/t/acme/members",
  "/t/acme/export",
  "/ops",
  "/account",
  "/nowhere",
];

async function watch(page: Page): Promise<string[]> {
  const violations: string[] = [];
  await page.exposeFunction("__cspViolation", (v: string) => violations.push(v));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      (window as unknown as { __cspViolation: (v: string) => void }).__cspViolation(
        `${e.violatedDirective} ${e.blockedURI}`,
      );
    });
  });
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/i.test(m.text())) violations.push(m.text());
  });
  return violations;
}

test("the build runs under the production CSP with no violations", async ({ page, state }) => {
  const violations = await watch(page);
  for (const path of PAGES) {
    const res = await page.goto(path);
    expect(res?.headers()["content-security-policy"]).toBe(CSP);
    await expect(page.locator("#app > *").first()).toBeVisible();
  }
  // Open the forms that render the most markup, too.
  await page.goto("/t/acme/roles");
  await page.getByRole("button", { name: "Add mount" }).click();
  await page.getByLabel("Type").selectOption("oidc");
  await page.locator('[data-testid="role-group"]').first().getByRole("button", { name: "Add role" }).click();
  // The Account page with a key, the browser fingerprint, a signing command and a removal open.
  state.fresh = true;
  state.sshKeys = { keys: [sshKey(KEYS.ed25519.line, { label: "laptop" })], unverified: [KEYS.sk.fingerprint] };
  await page.goto("/account");
  await page.getByLabel("Public key").fill(KEYS.ecdsa.line);
  await expect(page.getByTestId("browser-fingerprint")).toContainText(KEYS.ecdsa.fingerprint);
  await page.getByRole("button", { name: "Get a signing command" }).click();
  await expect(page.getByTestId("signing-command")).toBeVisible();
  await page.getByRole("button", { name: "Delete laptop" }).click();
  await expect(page.getByTestId("remove-confirm")).toBeVisible();
  await page.waitForTimeout(200);
  expect(violations).toEqual([]);
});

test("the built index.html has no inline script or style", async ({ page, state }) => {
  void state;
  const res = await page.request.get("/");
  const html = await res.text();
  expect(html).not.toMatch(/<style/i);
  expect(html).not.toMatch(/\sstyle=/i);
  for (const m of html.matchAll(/<script\b([^>]*)>/gi)) expect(m[1]).toMatch(/\bsrc=/);
});
