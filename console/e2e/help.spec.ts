import { GUIDE_URL } from "../src/lib/docs";
import { expect, test } from "./fixtures";

const external = async (link: import("@playwright/test").Locator, href: string) => {
  await expect(link).toHaveAttribute("href", href);
  await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  await expect(link).toHaveAttribute("target", "_blank");
};

test("the footer links the guide and the CLI install, signed in or not", async ({ page, state }) => {
  void state;
  for (const path of ["/signin", "/"]) {
    await page.goto(path);
    const footer = page.locator("footer");
    await external(footer.getByRole("link", { name: "User guide" }), GUIDE_URL);
    await external(
      footer.getByRole("link", { name: "Install the CLI" }),
      `${GUIDE_URL}#install-the-cli`,
    );
  }
});

test("Roles, Policies and Export link their guide sections", async ({ page, state }) => {
  void state;
  const cases = [
    ["/t/acme/roles", "roles-help", "#mounts-and-roles"],
    ["/t/acme/policies", "policies-help", "#policies"],
    ["/t/acme/export", "export-help", "#export"],
  ] as const;
  for (const [path, id, anchor] of cases) {
    await page.goto(path);
    await external(page.getByTestId(id).getByRole("link"), GUIDE_URL + anchor);
  }
});
