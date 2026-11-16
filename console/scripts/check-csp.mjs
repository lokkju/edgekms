// Fails the build when dist/index.html has anything the production CSP would refuse: an inline
// <script> (one without src), any <style> element, or a style= attribute. It also refuses
// style= anywhere in the built JS, since Svelte would set it at runtime.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;
const html = readFileSync(join(dist, "index.html"), "utf8");
const problems = [];

for (const m of html.matchAll(/<script\b([^>]*)>/gi)) {
  if (!/\bsrc\s*=/i.test(m[1] ?? "")) problems.push(`inline script: ${m[0]}`);
}
if (/<style\b/i.test(html)) problems.push("a <style> element");
if (/\sstyle\s*=/i.test(html)) problems.push("a style= attribute");
if (/\son[a-z]+\s*=/i.test(html)) problems.push("an inline event handler attribute");

for (const f of readdirSync(join(dist, "assets"))) {
  if (!f.endsWith(".js")) continue;
  const js = readFileSync(join(dist, "assets", f), "utf8");
  if (/\bstyle="/.test(js)) problems.push(`style="..." in assets/${f}`);
}

if (problems.length > 0) {
  console.error("check-csp: the build would break the console CSP:");
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("check-csp: dist/index.html has no inline script, style or style= attribute");
