// Prints the notices for the npm packages whose code is in the web console's bundle.
//
//   node console-notices.mjs <build dir>
//
// <build dir> is a `vite build --sourcemap` output. Every source map lists the files the bundle
// was made from; each one under node_modules names a package, and that package's license file
// (with its copyright line) is printed. Build-only packages (vite, typescript, the test tools)
// never reach a source map, so they are left out.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve, dirname, sep } from "node:path";

const buildDir = process.argv[2] && resolve(process.argv[2]);
if (!buildDir) {
  console.error("usage: console-notices.mjs <build dir>");
  process.exit(2);
}

function maps(dir) {
  return readdirSync(dir, { recursive: true })
    .map((f) => join(dir, f))
    .filter((f) => f.endsWith(".map") && statSync(f).isFile());
}

// The package root for a file path: the directory after the last node_modules segment (two
// segments for a scoped name).
function packageRoot(file) {
  const parts = file.split(sep);
  const i = parts.lastIndexOf("node_modules");
  if (i < 0) return null;
  const n = parts[i + 1]?.startsWith("@") ? 2 : 1;
  return parts.slice(0, i + 1 + n).join(sep);
}

const roots = new Set();
for (const map of maps(buildDir)) {
  const { sources = [], sourceRoot = "" } = JSON.parse(readFileSync(map, "utf8"));
  for (const s of sources) {
    const root = packageRoot(resolve(dirname(map), sourceRoot, s));
    if (root) roots.add(root);
  }
}
if (roots.size === 0) {
  console.error(`no node_modules sources in the source maps under ${buildDir}`);
  process.exit(1);
}

const licenseFile = /^(licen[cs]e|copying|notice)(\.(md|txt|markdown))?$/i;
const pkgs = [...roots]
  .map((root) => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    const files = readdirSync(root).filter((f) => licenseFile.test(f)).sort();
    const repo = typeof pkg.repository === "string" ? pkg.repository : pkg.repository?.url;
    return { root, name: pkg.name, version: pkg.version, license: pkg.license, repo, files };
  })
  .sort((a, b) => a.name.localeCompare(b.name));

const out = [];
out.push("npm packages bundled into the edgekms web console", "=".repeat(49), "");
for (const p of pkgs) out.push(`- ${p.name} ${p.version}: ${p.license ?? "no license field"}`);
out.push("");
let missing = 0;
for (const p of pkgs) {
  out.push("-".repeat(80), `${p.name} ${p.version} (${p.license ?? "no license field"})`);
  if (p.repo) out.push(p.repo);
  out.push("");
  if (p.files.length === 0) {
    missing++;
    console.error(`${p.name} ${p.version} has no license file in ${p.root}`);
  }
  for (const f of p.files) out.push(readFileSync(join(p.root, f), "utf8").trimEnd(), "");
}
if (missing > 0) process.exit(1);
process.stdout.write(out.join("\n") + "\n");
