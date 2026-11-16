import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// The production CSP (deploy sets it on every app.<apex> response). `vite preview` sends it too,
// so the Playwright run proves the built SPA works under it.
export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "font-src 'self'; connect-src 'self' https://api.github.com; base-uri 'none'; " +
  "form-action 'self'; frame-ancestors 'none'";

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  build: {
    // The polyfill is an inline script; the CSP refuses it.
    modulePreload: { polyfill: false },
    assetsDir: "assets",
    // Every asset is a file: an inlined data: URL for a script or style would break the CSP.
    assetsInlineLimit: 0,
  },
  preview: {
    headers: { "Content-Security-Policy": CSP },
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
