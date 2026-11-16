// The GitHub Actions role preset. A role binds the repository and owner by numeric id: a name can
// be renamed, or deleted and registered again by someone else, and a role bound to the name would
// trust them.

import { GITHUB_ACTIONS_MOUNT, type ClaimMatch, type Mount } from "./config";

/** GitHub's owner and repository name rules, loosely: what may follow github.com/. */
const SEGMENT = /^[A-Za-z0-9_.-]+$/;

/** `owner/repo`, or a github.com URL of one, as its two parts. */
export function parseRepoSlug(input: string): { owner: string; repo: string } | null {
  const s = input
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/^github\.com\//, "")
    .replace(/\/$/, "")
    .replace(/\.git$/, "");
  const parts = s.split("/");
  if (parts.length !== 2) return null;
  const [owner, repo] = parts as [string, string];
  for (const p of [owner, repo]) {
    if (!SEGMENT.test(p) || p === "." || p === "..") return null;
  }
  return { owner, repo };
}

const glob = (value: string): ClaimMatch => (value.includes("*") ? { glob: value } : value);

/**
 * The bound claims for a repository: its id and its owner's id, as the strings GitHub's token
 * carries (a number never matches), plus `ref` for a branch (or a full `refs/...` ref) and
 * `environment` when given. A `*` in either makes it a glob.
 */
export function actionsClaims(opts: {
  repositoryId: number;
  ownerId: number;
  branch?: string;
  environment?: string;
}): Record<string, ClaimMatch> {
  const claims: Record<string, ClaimMatch> = {
    repository_id: String(opts.repositoryId),
    repository_owner_id: String(opts.ownerId),
  };
  const branch = opts.branch?.trim() ?? "";
  if (branch !== "") claims.ref = glob(branch.startsWith("refs/") ? branch : `refs/heads/${branch}`);
  const environment = opts.environment?.trim() ?? "";
  if (environment !== "") claims.environment = glob(environment);
  return claims;
}

/**
 * The tenant's own origin, from the console's: the console is the hosted origin template with
 * `app` for the tenant, so `https://app.edgekms.dev` gives `https://<tenant>.edgekms.dev`. Null
 * when the console isn't on an `app.` host (a local preview).
 */
export function tenantOrigin(consoleOrigin: string, tenant: string): string | null {
  const m = /^(https?:\/\/)app\.(.+)$/.exec(consoleOrigin);
  return m ? `${m[1]}${tenant}.${m[2]}` : null;
}

/** Whether a mount is GitHub Actions' OIDC issuer. */
export function isGithubActions(mount: Mount): boolean {
  const preset = GITHUB_ACTIONS_MOUNT as Extract<Mount, { type: "jwt" }>;
  return mount.type === "jwt" && mount.issuer === preset.issuer;
}

/** Claims whose value is a name that can be renamed and taken by someone else. */
const NAME_CLAIMS = new Set(["repository", "repository_owner"]);

export function nameClaim(claim: string): boolean {
  return NAME_CLAIMS.has(claim.trim());
}
