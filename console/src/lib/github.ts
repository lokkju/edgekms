// Login to GitHub id, from the browser. Members, invites, the allowlist and github-user roles are
// keyed by id, since a login can be renamed and taken by someone else. The lookup is
// unauthenticated and sends no credentials.

export interface GithubAccount {
  id: number;
  login: string;
}

export interface GithubRepo {
  id: number;
  fullName: string;
  ownerId: number;
  ownerLogin: string;
}

/** GETs a public api.github.com path: the JSON body, or null on a 404. */
async function github(path: string): Promise<unknown> {
  const res = await fetch("https://api.github.com" + path, {
    headers: { Accept: "application/vnd.github+json" },
    credentials: "omit",
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    let detail = `GitHub lookup failed (${res.status})`;
    try {
      const body = (await res.json()) as { message?: unknown };
      if (typeof body.message === "string") detail = `GitHub lookup failed: ${body.message}`;
    } catch {
      // Keep the status-only message.
    }
    throw new Error(detail);
  }
  return res.json();
}

/** A repository's id and its owner's id. Null when GitHub has no such public repository. */
export async function resolveRepo(owner: string, repo: string): Promise<GithubRepo | null> {
  const body = (await github(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
  )) as { id?: unknown; full_name?: unknown; owner?: { id?: unknown; login?: unknown } } | null;
  if (body === null) return null;
  const o = body.owner;
  if (
    typeof body.id !== "number" ||
    typeof body.full_name !== "string" ||
    typeof o?.id !== "number" ||
    typeof o.login !== "string"
  ) {
    throw new Error("GitHub returned a repository without its ids");
  }
  return { id: body.id, fullName: body.full_name, ownerId: o.id, ownerLogin: o.login };
}

export async function resolveLogin(login: string): Promise<GithubAccount | null> {
  const name = login.trim().replace(/^@/, "");
  if (name === "") return null;
  const body = (await github("/users/" + encodeURIComponent(name))) as {
    id?: unknown;
    login?: unknown;
  } | null;
  if (body === null) return null;
  if (typeof body.id !== "number" || typeof body.login !== "string") {
    throw new Error("GitHub returned an account without an id");
  }
  return { id: body.id, login: body.login };
}

/** A GitHub account as the Ops page shows it beside an invite request. */
export interface GithubProfile {
  id: number;
  login: string;
  /** When the account was created (Unix milliseconds), if GitHub said. */
  createdMs: number | null;
  publicRepos: number | null;
}

/** Accounts by id, for this page load only (memory, never browser storage). */
const accountCache = new Map<number, Promise<GithubProfile | null>>();

/**
 * A GitHub account by id: its current login, creation date and public repository count. Null when
 * it can't be had (no such account, a rate limit, no network). Each id is asked for once per page
 * load, shared with {@link loginForId}.
 */
export function accountById(id: number): Promise<GithubProfile | null> {
  if (!Number.isInteger(id) || id <= 0) return Promise.resolve(null);
  let found = accountCache.get(id);
  if (found === undefined) {
    found = github(`/user/${id}`)
      .then((body) => {
        const b = body as { login?: unknown; created_at?: unknown; public_repos?: unknown } | null;
        if (typeof b?.login !== "string") return null;
        const created = typeof b.created_at === "string" ? Date.parse(b.created_at) : NaN;
        return {
          id,
          login: b.login,
          createdMs: Number.isFinite(created) ? created : null,
          publicRepos: typeof b.public_repos === "number" ? b.public_repos : null,
        };
      })
      .catch(() => null);
    accountCache.set(id, found);
  }
  return found;
}

/**
 * The current login of a GitHub account, by id, for display. Null when it can't be had (no such
 * account, a rate limit, no network): the caller shows the id. Each id is asked for once per page
 * load.
 */
export function loginForId(id: number): Promise<string | null> {
  return accountById(id).then((a) => a?.login ?? null);
}
