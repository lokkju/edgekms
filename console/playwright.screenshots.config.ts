import { defineConfig, devices } from "@playwright/test";
import base from "./playwright.config";

// The user guide's screenshots (docs/images/console/), from the production build against the
// in-memory fake backend. Not part of `pnpm e2e` or CI: run `pnpm screenshots` after a UI change
// and commit the PNGs it writes.
export default defineConfig({
  ...base,
  testMatch: "*.shot.ts",
  fullyParallel: false,
  retries: 0,
  reporter: "list",
  projects: [
    {
      name: "screenshots",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1100, height: 720 },
        deviceScaleFactor: 1,
        colorScheme: "light",
      },
    },
  ],
});
