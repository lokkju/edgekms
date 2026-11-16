// The control API, same origin, under /api/v1. The session cookie is HttpOnly: this module never
// sees the control token, and nothing here may try to read or store it.

import type { Config } from "./config";

export type MemberRole = "owner" | "member";
export type TenantStatus = "active" | "suspended";

export interface TenantSummary {
  name: string;
  role: MemberRole;
  status: TenantStatus;
}

export interface InviteSummary {
  name: string;
  role: MemberRole;
}

export interface Me {
  github_id: number;
  login: string;
  operator: boolean;
  tenants: TenantSummary[];
  invites: InviteSummary[];
}

export interface Seat {
  github_id: number;
  role: MemberRole;
}

export interface TenantDetail {
  name: string;
  id: string;
  root_id: string;
  status: TenantStatus;
  config: Config;
  config_version: number;
  members: Seat[];
  invites: Seat[];
}

export interface Created {
  name: string;
  id: string;
  root_id: string;
  config_version: number;
}

export interface Exported {
  root_id: string;
  root_key: string;
}

export interface AllowEntry {
  github_id: number;
  added_by: number;
  added_ms: number;
}

export interface Allowlist {
  allowlist: AllowEntry[];
  unverified: number[];
}

export type InviteStatus = "pending" | "approved" | "declined";

/** `GET /invite-requests/mine`, with the request cookie: the refused user's own request. */
export interface MyInviteRequest {
  github_id: number;
  login: string;
  accepting: boolean;
  request: null | { status: InviteStatus; created_ms: number; decided_ms: number | null };
}

/** One request on the Ops page. `note` is plain text: render it as text, never as HTML. */
export interface InviteRequest {
  github_id: number;
  login: string;
  note: string;
  created_ms: number;
  status: InviteStatus;
  decided_by: number | null;
  decided_ms: number | null;
}

export interface InviteRequestList {
  requests: InviteRequest[];
  unverified: number[];
  pending: number;
}

/** One SSH key that can log in to the control plane as the user. */
export interface SshKey {
  /** The fingerprint's base64 in base64url, 43 characters: the key's name in routes. */
  id: string;
  fingerprint: string;
  key_type: string;
  public_key: string;
  label: string;
  added_ms: number;
  /** `github`, or `ssh:<fingerprint>` naming the key behind the session that added it. */
  added_via: string;
  last_used_ms: number | null;
}

/** `GET /me/ssh-keys`. `unverified` holds the fingerprints of rows that fail their MAC. */
export interface SshKeyList {
  keys: SshKey[];
  unverified: string[];
}

/** `POST /me/ssh-keys/challenge`. */
export interface SshKeyChallenge {
  challenge: string;
  expires_in: number;
  namespace: string;
  /** The account the challenge names; the page reads it from the challenge itself. */
  github_id: number;
  login: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly messages: string[];
  /** True when the session is gone and the browser is already on its way to sign in. */
  readonly reauth: boolean;

  constructor(status: number, messages: string[], code?: string, reauth = false) {
    super(messages[0] ?? `request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.messages = messages;
    this.reauth = reauth;
  }
}

/** The codes that mean "your session no longer works", as opposed to "you may not". */
const REAUTH = new Set(["no_session", "auth_failed"]);

/** How long after a sign-in a refused session means the login itself is broken. */
const SIGN_IN_GRACE_MS = 10_000;

/** When this page load arrived from a completed sign-in, if it did. Memory only. */
let signedInAt: number | null = null;

/**
 * Reads the `signed_in=1` mark the Worker adds to the address after a sign-in, and removes it
 * from the address bar. Call once on load, before the router reads the address. A session
 * refused within a few seconds of that sign-in can't be fixed by signing in again (it would
 * loop through GitHub), so {@link request} reports a failed login instead.
 */
export function noteSignIn(): void {
  const params = location.search.replace(/^\?/, "").split("&").filter((p) => p !== "");
  const rest = params.filter((p) => p !== "signed_in=1");
  if (rest.length === params.length) {
    signedInAt = null;
    return;
  }
  signedInAt = Date.now();
  const search = rest.length > 0 ? "?" + rest.join("&") : "";
  history.replaceState(history.state, "", location.pathname + search + location.hash);
}

/** A control session lasts this long from sign-in, however active (the session cookie's Max-Age). */
const SESSION_MS = 30 * 60_000;

/** How long before the session ends the console warns. */
const WARN_BEFORE_MS = 5 * 60_000;

/** When this page load's session began, if it arrived from a sign-in; otherwise unknown. */
export function sessionStartedAt(): number | null {
  return signedInAt;
}

/**
 * Milliseconds from `now` until the session expiry warning shows: 0 when it's already due, null
 * when the session start is unknown (the page wasn't loaded from a sign-in) or it has ended.
 */
export function expiryWarningDelay(startedAt: number | null, now: number): number | null {
  if (startedAt === null) return null;
  const elapsed = now - startedAt;
  if (elapsed >= SESSION_MS) return null;
  return Math.max(0, SESSION_MS - WARN_BEFORE_MS - elapsed);
}

function justSignedIn(): boolean {
  return signedInAt !== null && Date.now() - signedInAt < SIGN_IN_GRACE_MS;
}

export function signIn(returnTo: string): void {
  location.assign("/auth/login?return_to=" + encodeURIComponent(returnTo));
}

/**
 * Ends every control session of the user. Rejects unless the server confirms with a 204; on a
 * failure the server keeps the session cookie, so the user is still signed in.
 */
export async function signOut(): Promise<void> {
  let res: Response;
  try {
    res = await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch {
    throw new ApiError(0, ["the network request failed"]);
  }
  if (res.status !== 204) {
    const { messages, code } = await errorBody(res);
    throw new ApiError(res.status, messages, code);
  }
}

async function errorBody(res: Response): Promise<{ messages: string[]; code?: string }> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object") {
      const { errors, code } = body as { errors?: unknown; code?: unknown };
      const messages = Array.isArray(errors)
        ? errors.filter((e): e is string => typeof e === "string")
        : [];
      return {
        messages: messages.length > 0 ? messages : [`request failed (${res.status})`],
        code: typeof code === "string" ? code : undefined,
      };
    }
  } catch {
    // Not JSON; fall through.
  }
  return { messages: [`request failed (${res.status})`] };
}

/**
 * Calls `/api/v1<path>` and resolves to the reply's `data`, or `undefined` on a 204. A reply
 * that says the session is gone sends the browser to sign in (or, right after a sign-in, to
 * `/signin?error=login_failed`) and rejects with `reauth` set, unless `reauth` is false: the
 * invite request page answers a refusal itself, since signing in again there would lose what the
 * user typed.
 */
export async function request<T>(
  method: string,
  path: string,
  opts: { body?: unknown; ifMatch?: number; reauth?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (opts.ifMatch !== undefined) headers["If-Match"] = `"${opts.ifMatch}"`;

  let res: Response;
  try {
    res = await fetch("/api/v1" + path, { method, headers, body, credentials: "same-origin" });
  } catch {
    throw new ApiError(0, ["the network request failed"]);
  }

  if (res.status === 204) return undefined as T;
  if (res.ok) {
    const json = (await res.json()) as { data?: T };
    return json.data as T;
  }
  const { messages, code } = await errorBody(res);
  if (code !== undefined && REAUTH.has(code) && opts.reauth !== false) {
    if (justSignedIn()) location.assign("/signin?error=login_failed");
    else signIn(location.pathname);
    throw new ApiError(res.status, messages, code, true);
  }
  throw new ApiError(res.status, messages, code);
}

export const me = (): Promise<Me> => request<Me>("GET", "/me");

export const tenantPath = (name: string): string => "/tenants/" + encodeURIComponent(name);
