import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GUIDE_ANCHORS, GUIDE_URL, guide } from "./docs";

const GUIDE = readFileSync(new URL("../../../docs/console.md", import.meta.url), "utf8");

/** GitHub's anchor for a Markdown heading: lowercased, punctuation dropped, spaces as hyphens. */
function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

const anchors = new Set(
  GUIDE.split("\n")
    .filter((l) => /^#{1,6}\s/.test(l))
    .map((l) => slug(l.replace(/^#+\s/, ""))),
);

describe("guide links", () => {
  it("point at headings the guide has", () => {
    for (const anchor of Object.values(GUIDE_ANCHORS)) expect(anchors).toContain(anchor);
  });

  it("build GitHub URLs", () => {
    expect(guide()).toBe(GUIDE_URL);
    expect(guide("export")).toBe(`${GUIDE_URL}#export`);
  });

  it("slug headings the way GitHub does", () => {
    expect(slug("A teammate's GitHub account")).toBe("a-teammates-github-account");
    expect(slug("Install the CLI")).toBe("install-the-cli");
  });
});
