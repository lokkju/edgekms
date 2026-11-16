// Links from the console to its user guide, docs/console.md. Until the docs site exists (#32),
// the guide is read on GitHub. docs.test.ts checks that every anchor here is a heading there.

export const GUIDE_URL = "https://github.com/lokkju/edgekms/blob/main/docs/console.md";

/** The guide's sections the console links to, by GitHub's heading anchor. */
export const GUIDE_ANCHORS = {
  roles: "mounts-and-roles",
  policies: "policies",
  export: "export",
  cli: "install-the-cli",
} as const;

export function guide(section?: keyof typeof GUIDE_ANCHORS): string {
  return section === undefined ? GUIDE_URL : `${GUIDE_URL}#${GUIDE_ANCHORS[section]}`;
}
