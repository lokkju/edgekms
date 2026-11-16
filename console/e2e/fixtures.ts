// An in-memory fake of the console's API contract (the control plane routes the console calls; see
// docs/specs/2026-11-10-web-console-design.md), served through page.route, plus the /auth/* routes
// and api.github.com.

import { createHash } from "node:crypto";
import { test as base, expect, type Page, type Route } from "@playwright/test";
import type {
  Allowlist,
  InviteRequestList,
  Me,
  MyInviteRequest,
  SshKey,
  SshKeyList,
  TenantDetail,
} from "../src/lib/api";

export interface Recorded {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

/** The refused user behind the request cookie, for `/request-invite`. */
export interface FakeRequester {
  /** `ok` sends the request cookie; `null` none (401 `no_request_session`); `expired` 403. */
  session: "ok" | "expired" | null;
  github_id: number;
  login: string;
  accepting: boolean;
  request: MyInviteRequest["request"];
  /** When set, the next `POST /invite-requests` answers with this refusal. */
  refuse: null | { status: number; code: string; message: string };
  /** The notes `POST /invite-requests` received. */
  filed: string[];
}

/** What `POST /invite-requests` reports as its filing time: 2026-11-11. */
export const FILED_MS = 1_794_355_200_000;

/** Fixture public keys made with ssh-keygen; the fingerprints are what `ssh-keygen -lf` prints. */
export const KEYS = {
  ed25519: {
    line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDkBO98B+KFd8sDdoOSJYGv7EL8kIm1Stu7PdZzX3CXG nick@laptop",
    fingerprint: "SHA256:EElDPqD3VfhASD1R+/l1pnDKkILTpdfv5Fp4xMVYZXE",
  },
  ecdsa: {
    line: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJO4kQb9ilcQAbuq9tdm0VJKzxkqBn/Imeqta7mcVNcIVCox1jqV6I92fZILz89Pjn0yCUwv6jPjd72SdE7SOjA= work ecdsa",
    fingerprint: "SHA256:0kvU8VadKghlGEtpRk1TuZzWHU2DRhgHfXE5CX+qVSk",
  },
  sk: {
    line: "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyucDHztXcAAAABHNzaDo= yubikey-5c",
    fingerprint: "SHA256:83ny0sBD6XvpUfb31f8h4vb4GZRmF5WvKEmNe8GtLQU",
  },
} as const;

/** A fake signature block; the fake checks only its armor. */
export const SIGNATURE =
  "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\n-----END SSH SIGNATURE-----";

/** The key object the control plane lists for `line`, as it would store it. */
export function sshKey(line: string, fields: Partial<SshKey> = {}): SshKey {
  const [type = "", b64 = ""] = line.split(" ");
  const fingerprint =
    "SHA256:" + createHash("sha256").update(Buffer.from(b64, "base64")).digest("base64").replace(/=+$/, "");
  return {
    id: fingerprint.slice(7).replace(/\+/g, "-").replace(/\//g, "_"),
    fingerprint,
    key_type: type,
    public_key: `${type} ${b64}`,
    label: "",
    added_ms: FILED_MS,
    added_via: "github",
    last_used_ms: null,
    ...fields,
  };
}

export interface FakeState {
  me: Me;
  /** The caller's SSH keys, as `GET /me/ssh-keys` lists them. */
  sshKeys: SshKeyList;
  /** The registration challenges handed out, oldest first. */
  sshChallenges: string[];
  /** When set, registration challenges name this account rather than `me`'s. */
  sshChallengeAccount: null | { github_id: number; login: string };
  /** When set, the next `POST /me/ssh-keys` answers with this refusal. */
  sshAddRefuse: null | { status: number; code: string; message: string };
  requester: FakeRequester;
  tenants: Record<string, TenantDetail>;
  allowlist: Allowlist;
  inviteRequests: InviteRequestList;
  githubUsers: Record<string, number>;
  /** Extra fields `GET api.github.com/user/:id` answers with, by id. */
  githubProfiles: Record<number, { login: string; created_at: string; public_repos: number }>;
  /** Public repositories at api.github.com, by lowercase `owner/repo`. */
  githubRepos: Record<string, { id: number; full_name: string; owner: { id: number; login: string } }>;
  /** Whether the session is a fresh login (export needs one). */
  fresh: boolean;
  /** When set, every API call answers with this session failure. */
  session: null | "no_session" | "auth_failed";
  /** When true, the next config PUT finds that someone else saved first. */
  conflictNext: boolean;
  /** Whether a sign-in clears `session`; when false, the session stays broken after it. */
  loginFixes: boolean;
  /** The status `POST /auth/logout` answers with. */
  logoutStatus: number;
  requests: Recorded[];
  logins: string[];
}

export function initialState(): FakeState {
  const config = {
    root_id: "r_acme",
    keys: { default: { id: "k_00000000000000aa", latest_version: 1, min_decryption_version: 1 } },
    mounts: { "github-user": { type: "github-user" as const, client_id: "Iv23liEdgekms" } },
    roles: {
      owner: {
        mount: "github-user",
        github_user_ids: [1001],
        policies: ["admin", "default-all"],
        token_ttl_secs: 3600,
      },
    },
    policies: {
      admin: { admin: ["token-create" as const, "token-revoke" as const] },
      "default-all": { keys: { default: ["encrypt" as const, "decrypt" as const, "rewrap" as const, "read" as const] } },
    },
  };
  return {
    requester: {
      session: "ok",
      github_id: 2002,
      login: "carol",
      accepting: true,
      request: null,
      refuse: null,
      filed: [],
    },
    me: {
      github_id: 1001,
      login: "alice",
      operator: true,
      tenants: [
        { name: "acme", role: "owner", status: "active" },
        { name: "frozen", role: "member", status: "suspended" },
      ],
      invites: [{ name: "beta", role: "member" }],
    },
    tenants: {
      acme: {
        name: "acme",
        id: "t_acme",
        root_id: "r_acme",
        status: "active",
        config,
        config_version: 3,
        members: [{ github_id: 1001, role: "owner" }],
        invites: [],
      },
    },
    allowlist: { allowlist: [{ github_id: 7, added_by: 1001, added_ms: 1_790_000_000_000 }], unverified: [] },
    inviteRequests: { requests: [], unverified: [], pending: 0 },
    githubUsers: { bob: 4242, alice: 1001 },
    githubProfiles: {},
    githubRepos: {
      "acme/app": { id: 812345678, full_name: "acme/app", owner: { id: 1234567, login: "acme" } },
    },
    fresh: false,
    session: null,
    conflictNext: false,
    loginFixes: true,
    logoutStatus: 204,
    requests: [],
    logins: [],
    sshKeys: { keys: [], unverified: [] },
    sshChallenges: [],
    sshChallengeAccount: null,
    sshAddRefuse: null,
  };
}

const json = (route: Route, status: number, body?: unknown) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: body === undefined ? "" : JSON.stringify(body),
  });

const error = (route: Route, status: number, message: string, code?: string) =>
  json(route, status, code ? { errors: [message], code } : { errors: [message] });

async function handleRequester(
  state: FakeState,
  route: Route,
  method: string,
  path: string,
  body: unknown,
): Promise<void> {
  const r = state.requester;
  if (r.session === null) return error(route, 401, "sign in to request an invite", "no_request_session");
  if (r.session === "expired") return error(route, 403, "permission denied", "auth_failed");
  if (method === "GET" && path === "/invite-requests/mine") {
    return json(route, 200, {
      data: { github_id: r.github_id, login: r.login, accepting: r.accepting, request: r.request },
    });
  }
  if (method === "POST" && path === "/invite-requests") {
    if (r.refuse) {
      const { status, code, message } = r.refuse;
      r.refuse = null;
      return error(route, status, message, code);
    }
    const note = ((body as { note?: unknown } | undefined)?.note ?? "") as string;
    r.filed.push(note);
    r.request = { status: "pending", created_ms: FILED_MS, decided_ms: null };
    return json(route, 201, { data: { status: "pending", created_ms: FILED_MS } });
  }
  return error(route, 404, "unsupported path");
}

async function handleApi(state: FakeState, route: Route): Promise<void> {
  const req = route.request();
  const url = new URL(req.url());
  const path = url.pathname.replace(/^\/api\/v1/, "");
  const method = req.method();
  let body: unknown;
  try {
    body = req.postData() ? JSON.parse(req.postData() as string) : undefined;
  } catch {
    body = req.postData();
  }
  state.requests.push({ method, path, headers: await req.allHeaders(), body });

  // The two requester paths take the request cookie, never the session (the Worker's proxy).
  if (path === "/invite-requests" || path === "/invite-requests/mine") {
    return handleRequester(state, route, method, path, body);
  }

  if (state.session === "no_session") return error(route, 401, "sign in required", "no_session");
  if (state.session === "auth_failed") return error(route, 403, "permission denied", "auth_failed");

  const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  const [a, b, c, d] = parts;

  if (method === "GET" && a === "me" && parts.length === 1) return json(route, 200, { data: state.me });

  if (a === "tenants" && b !== undefined) {
    const t = state.tenants[b];
    if (method === "POST" && (c === "accept" || c === "decline")) {
      const invite = state.me.invites.find((i) => i.name === b);
      if (!invite) return error(route, 404, "no pending invite");
      state.me.invites = state.me.invites.filter((i) => i.name !== b);
      if (c === "accept") state.me.tenants.push({ name: b, role: invite.role, status: "active" });
      return route.fulfill({ status: 204 });
    }
    if (!t) return error(route, 404, "tenant not found");
    if (method === "GET" && parts.length === 2) return json(route, 200, { data: t });
    if (method === "PUT" && c === "config") {
      const ifMatch = req.headers()["if-match"];
      if (state.conflictNext) {
        state.conflictNext = false;
        t.config_version += 1;
        t.config = { ...t.config, keys: { ...t.config.keys, other: { id: "k_00000000000000bb", latest_version: 1, min_decryption_version: 1 } } };
        return error(route, 409, "config version mismatch");
      }
      if (ifMatch !== `"${t.config_version}"`) return error(route, 409, "config version mismatch");
      t.config = body as TenantDetail["config"];
      t.config_version += 1;
      return json(route, 200, { data: { config_version: t.config_version } });
    }
    if (c === "members" && d !== undefined) {
      const id = Number(d);
      if (method === "PUT") {
        const role = (body as { role: "owner" | "member" }).role;
        t.invites = [...t.invites.filter((i) => i.github_id !== id), { github_id: id, role }];
        return route.fulfill({ status: 204 });
      }
      if (method === "DELETE") {
        t.members = t.members.filter((m) => m.github_id !== id);
        t.invites = t.invites.filter((m) => m.github_id !== id);
        return route.fulfill({ status: 204 });
      }
    }
    if (method === "POST" && c === "export") {
      if (!state.fresh) return error(route, 403, "fresh login required", "fresh_login_required");
      return json(route, 200, {
        data: { root_id: t.root_id, root_key: "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=" },
      });
    }
  }

  if (a === "me" && b === "ssh-keys") {
    const keys = state.sshKeys;
    if (method === "GET" && c === undefined) return json(route, 200, { data: keys });
    if (method === "POST" && c === "challenge") {
      if (!state.fresh) return error(route, 403, "fresh login required", "fresh_login_required");
      const { github_id, login } = state.sshChallengeAccount ?? state.me;
      const n = state.sshChallenges.length + 1;
      const challenge = `ekmsr.${github_id}.${login}.FAKE${n}_AAECAwQFBgcICQoLDA0ODxAR-`;
      state.sshChallenges.push(challenge);
      return json(route, 200, {
        data: { challenge, expires_in: 300, namespace: "edgekms-register", github_id, login },
      });
    }
    if (method === "POST" && c === undefined) {
      if (!state.fresh) return error(route, 403, "fresh login required", "fresh_login_required");
      if (state.sshAddRefuse) {
        const { status, code, message } = state.sshAddRefuse;
        state.sshAddRefuse = null;
        return error(route, status, message, code);
      }
      const add = (body ?? {}) as Record<string, unknown>;
      const ok =
        typeof add.public_key === "string" &&
        typeof add.label === "string" &&
        typeof add.challenge === "string" &&
        state.sshChallenges.includes(add.challenge) &&
        typeof add.signature === "string" &&
        add.signature.startsWith("-----BEGIN SSH SIGNATURE-----");
      if (!ok) return error(route, 400, "ssh key proof failed", "ssh_key_proof_failed");
      const key = sshKey(add.public_key as string, { label: add.label as string });
      if (keys.keys.some((k) => k.fingerprint === key.fingerprint)) {
        return error(route, 409, "ssh key in use", "ssh_key_in_use");
      }
      keys.keys.push(key);
      return json(route, 201, { data: key });
    }
    if (method === "DELETE" && c !== undefined && d === undefined) {
      const fp = "SHA256:" + c.replace(/-/g, "+").replace(/_/g, "/");
      const known = keys.keys.some((k) => k.id === c) || keys.unverified.includes(fp);
      if (!known) return error(route, 404, "ssh key not found");
      keys.keys = keys.keys.filter((k) => k.id !== c);
      keys.unverified = keys.unverified.filter((u) => u !== fp);
      return route.fulfill({ status: 204 });
    }
  }

  if (a === "ops") {
    if (method === "GET" && b === "allowlist") return json(route, 200, { data: state.allowlist });
    if (b === "allowlist" && c !== undefined) {
      const id = Number(c);
      if (method === "PUT") {
        state.allowlist.allowlist.push({ github_id: id, added_by: state.me.github_id, added_ms: 1_790_000_000_000 });
        return route.fulfill({ status: 204 });
      }
      if (method === "DELETE") {
        state.allowlist.allowlist = state.allowlist.allowlist.filter((e) => e.github_id !== id);
        return route.fulfill({ status: 204 });
      }
    }
    if (method === "PUT" && b === "tenants" && d === "status") return route.fulfill({ status: 204 });
    if (b === "invite-requests") {
      const list = state.inviteRequests;
      const recount = () => {
        list.pending = list.requests.filter((r) => r.status === "pending").length;
      };
      if (method === "GET" && c === undefined) return json(route, 200, { data: list });
      const id = Number(c);
      if (method === "DELETE" && d === undefined) {
        const known =
          list.requests.some((r) => r.github_id === id) || list.unverified.includes(id);
        if (!known) return error(route, 404, "no invite request from that user", "request_not_found");
        list.requests = list.requests.filter((r) => r.github_id !== id);
        list.unverified = list.unverified.filter((u) => u !== id);
        recount();
        return route.fulfill({ status: 204 });
      }
      if (method === "POST" && (d === "approve" || d === "decline")) {
        const r = list.requests.find((x) => x.github_id === id);
        if (!r) return error(route, 404, "no invite request from that user", "request_not_found");
        if (r.status !== "pending") {
          return error(route, 409, "that request was already decided", "request_not_pending");
        }
        r.status = d === "approve" ? "approved" : "declined";
        r.decided_by = state.me.github_id;
        r.decided_ms = 1_790_000_000_000;
        if (d === "approve") {
          state.allowlist.allowlist.push({
            github_id: id,
            added_by: state.me.github_id,
            added_ms: 1_790_000_000_000,
          });
        }
        recount();
        return route.fulfill({ status: 204 });
      }
    }
  }

  return error(route, 404, "not found");
}

export async function fakeBackend(page: Page, state: FakeState): Promise<void> {
  await page.route("**/api/v1/**", (route) => handleApi(state, route));
  await page.route("**/auth/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/auth/logout") {
      if (state.logoutStatus === 204) return route.fulfill({ status: 204 });
      return error(route, state.logoutStatus, "audit log unavailable");
    }
    if (url.pathname === "/auth/login") {
      state.logins.push(url.search);
      // A real sign-in: GitHub, the callback, a fresh session, back to return_to.
      state.fresh = true;
      if (state.loginFixes) state.session = null;
      // The Worker marks the return path, as `flow::mark_signed_in` does.
      const back = url.searchParams.get("return_to") ?? "/";
      const sep = back.includes("?") ? "&" : "?";
      return route.fulfill({ status: 302, headers: { Location: back + sep + "signed_in=1" } });
    }
    return route.fulfill({ status: 404, body: "" });
  });
  await page.route("https://api.github.com/users/*", async (route) => {
    const login = decodeURIComponent(new URL(route.request().url()).pathname.split("/").pop() ?? "");
    const id = state.githubUsers[login.toLowerCase()];
    if (id === undefined) return json(route, 404, { message: "Not Found" });
    return json(route, 200, { id, login, type: "User" });
  });
  await page.route("https://api.github.com/user/*", async (route) => {
    const id = Number(new URL(route.request().url()).pathname.split("/").pop());
    const profile = state.githubProfiles[id];
    if (profile !== undefined) return json(route, 200, { id, type: "User", ...profile });
    const login = Object.entries(state.githubUsers).find(([, v]) => v === id)?.[0];
    if (login === undefined) return json(route, 404, { message: "Not Found" });
    return json(route, 200, { id, login, type: "User" });
  });
  await page.route("https://api.github.com/repos/*/*", async (route) => {
    const [, , owner, repo] = new URL(route.request().url()).pathname.split("/");
    const found = state.githubRepos[`${owner}/${repo}`.toLowerCase()];
    if (found === undefined) return json(route, 404, { message: "Not Found" });
    return json(route, 200, found);
  });
}

export const test = base.extend<{ state: FakeState }>({
  state: async ({ page }, use) => {
    const state = initialState();
    await fakeBackend(page, state);
    await use(state);
  },
});

export { expect };
