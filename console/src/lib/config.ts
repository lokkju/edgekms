// The tenant config, mirroring `crates/edgekms-core/src/config.rs`. The schema denies unknown
// fields everywhere, so nothing here may add a field that file doesn't have.

export type Capability = "encrypt" | "decrypt" | "rewrap" | "read";
export type AdminCapability = "token-create" | "token-revoke";

export interface KeyConfig {
  id: string;
  latest_version: number;
  min_decryption_version: number;
}

export type Mount =
  | { type: "jwt"; issuer: string; jwks_url?: string; jwks?: unknown }
  | { type: "ssh" }
  | { type: "github-user"; client_id: string };

export type ClaimMatch = string | { glob: string };

export interface Role {
  mount: string;
  bound_audiences?: string[];
  bound_claims?: Record<string, ClaimMatch>;
  ssh_keys?: string[];
  github_user_ids?: number[];
  policies: string[];
  token_ttl_secs: number;
  not_before?: number;
}

export interface Policy {
  keys?: Record<string, Capability[]>;
  admin?: AdminCapability[];
}

export interface Config {
  root_id: string;
  public_origins?: string[];
  keys: Record<string, KeyConfig>;
  mounts: Record<string, Mount>;
  roles: Record<string, Role>;
  policies: Record<string, Policy>;
}

export const CAPABILITIES: readonly Capability[] = ["encrypt", "decrypt", "rewrap", "read"];
export const ADMIN_CAPABILITIES: readonly AdminCapability[] = ["token-create", "token-revoke"];

/** GitHub Actions OIDC, the preset for a `jwt` mount. */
export const GITHUB_ACTIONS_MOUNT: Readonly<Mount> = Object.freeze({
  type: "jwt",
  issuer: "https://token.actions.githubusercontent.com",
  jwks_url: "https://token.actions.githubusercontent.com/.well-known/jwks",
});

const KEY_NAME = /^[A-Za-z0-9_-]{1,128}$/;

// JSON, not structuredClone: the editors hand in Svelte state proxies, which structuredClone
// refuses. A config is JSON by definition, so nothing is lost.
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function copy(c: Config): Config {
  return clone(c);
}

function has(obj: object, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, name);
}

function rolesUsing(c: Config, pred: (r: Role) => boolean): string[] {
  return Object.entries(c.roles)
    .filter(([, r]) => pred(r))
    .map(([n]) => n);
}

/** `k_` and 16 random lowercase hex digits. */
export function newKeyId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return "k_" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function addKey(c: Config, name: string): Config {
  if (!KEY_NAME.test(name)) throw new Error("a key name is 1 to 128 of A-Za-z0-9_-");
  if (has(c.keys, name)) throw new Error(`a key named ${name} already exists`);
  const ids = new Set(Object.values(c.keys).map((k) => k.id));
  let id = newKeyId();
  while (ids.has(id)) id = newKeyId();
  const next = copy(c);
  next.keys[name] = { id, latest_version: 1, min_decryption_version: 1 };
  return next;
}

/** The largest key version: `latest_version` is a `u32` in config.rs. */
export const MAX_KEY_VERSION = 4_294_967_295;

function keyNamed(c: Config, name: string): KeyConfig {
  const key = has(c.keys, name) ? c.keys[name] : undefined;
  if (!key) throw new Error(`no key named ${name}`);
  return key;
}

/** Rotates a key: new ciphertext uses the next version, and old ciphertext still decrypts. */
export function rotateKey(c: Config, name: string): Config {
  const key = keyNamed(c, name);
  if (key.latest_version >= MAX_KEY_VERSION) {
    throw new Error(`key ${name} is at the largest version`);
  }
  const next = copy(c);
  next.keys[name]!.latest_version = key.latest_version + 1;
  return next;
}

/**
 * Raises a key's minimum decryption version. Ciphertext under an older version stops decrypting
 * (config.rs requires 1 <= min_decryption_version <= latest_version); lowering it again brings
 * those versions back, since nothing is deleted, but that is the Raw JSON tab's job.
 */
export function raiseMinDecryption(c: Config, name: string, version: number): Config {
  const key = keyNamed(c, name);
  if (!Number.isInteger(version)) throw new Error("a version is a whole number");
  if (version <= key.min_decryption_version) {
    throw new Error(`the new minimum must be above ${key.min_decryption_version}`);
  }
  if (version > key.latest_version) {
    throw new Error(`the minimum can be at most ${key.latest_version}, the latest version`);
  }
  const next = copy(c);
  next.keys[name]!.min_decryption_version = version;
  return next;
}

export function addMount(c: Config, name: string, mount: Mount): Config {
  if (name === "") throw new Error("a mount needs a name");
  if (has(c.mounts, name)) throw new Error(`a mount named ${name} already exists`);
  const next = copy(c);
  next.mounts[name] = clone(mount) as Mount;
  return next;
}

export function setMount(c: Config, name: string, mount: Mount): Config {
  const next = copy(c);
  next.mounts[name] = clone(mount) as Mount;
  return next;
}

export function renameMount(c: Config, from: string, to: string): Config {
  if (from === to) return c;
  if (to === "") throw new Error("a mount needs a name");
  if (has(c.mounts, to)) throw new Error(`a mount named ${to} already exists`);
  if (!has(c.mounts, from)) throw new Error(`no mount named ${from}`);
  const next = copy(c);
  // Rebuilt so the renamed mount keeps its place in the order the user sees.
  next.mounts = Object.fromEntries(
    Object.entries(next.mounts).map(([n, m]) => (n === from ? [to, m] : [n, m])),
  );
  for (const r of Object.values(next.roles)) if (r.mount === from) r.mount = to;
  return next;
}

export function removeMount(c: Config, name: string): Config {
  const users = rolesUsing(c, (r) => r.mount === name);
  if (users.length > 0) throw new Error(`mount ${name} is used by role ${users.join(", ")}`);
  const next = copy(c);
  delete next.mounts[name];
  return next;
}

/** Adds or replaces role `name`; with `previous`, renames that role to `name`. */
export function upsertRole(c: Config, name: string, role: Role, previous?: string): Config {
  if (name === "") throw new Error("a role needs a name");
  const renaming = previous !== undefined && previous !== name;
  if (renaming && has(c.roles, name)) throw new Error(`a role named ${name} already exists`);
  const next = copy(c);
  if (renaming) {
    next.roles = Object.fromEntries(
      Object.entries(next.roles).map(([n, r]) => (n === previous ? [name, r] : [n, r])),
    );
  }
  next.roles[name] = clone(role);
  return next;
}

export function removeRole(c: Config, name: string): Config {
  const next = copy(c);
  delete next.roles[name];
  return next;
}

/** Whether role `name` holds a policy with any admin capability. */
export function holdsAdmin(c: Config, name: string): boolean {
  const role = c.roles[name];
  if (!role) return false;
  return role.policies.some((p) => (c.policies[p]?.admin?.length ?? 0) > 0);
}

/**
 * The role with only the fields its mount type accepts, and with empty optional fields left
 * out. The server refuses an SSH role that sets `bound_audiences`, for example, so a form that
 * switched mount type must not leave the old type's fields behind.
 */
export function cleanRole(role: Role, type: Mount["type"]): Role {
  const out: Role = {
    mount: role.mount,
    policies: [...role.policies],
    token_ttl_secs: role.token_ttl_secs,
  };
  if (type === "jwt") {
    if (role.bound_audiences?.length) out.bound_audiences = [...role.bound_audiences];
    if (role.bound_claims && Object.keys(role.bound_claims).length > 0) {
      out.bound_claims = clone(role.bound_claims);
    }
  } else if (type === "ssh") {
    if (role.ssh_keys?.length) out.ssh_keys = [...role.ssh_keys];
  } else if (role.github_user_ids?.length) {
    out.github_user_ids = [...role.github_user_ids];
  }
  if (role.not_before) out.not_before = role.not_before;
  return out;
}

export function addPolicy(c: Config, name: string): Config {
  if (name === "") throw new Error("a policy needs a name");
  if (has(c.policies, name)) throw new Error(`a policy named ${name} already exists`);
  const next = copy(c);
  next.policies[name] = {};
  return next;
}

export function removePolicy(c: Config, name: string): Config {
  const users = rolesUsing(c, (r) => r.policies.includes(name));
  if (users.length > 0) throw new Error(`policy ${name} is used by role ${users.join(", ")}`);
  const next = copy(c);
  delete next.policies[name];
  return next;
}

export function setCapability(
  c: Config,
  policy: string,
  key: string,
  cap: Capability,
  on: boolean,
): Config {
  const next = copy(c);
  const p = (next.policies[policy] ??= {});
  const keys = (p.keys ??= {});
  const caps = new Set(keys[key] ?? []);
  if (on) caps.add(cap);
  else caps.delete(cap);
  // The server refuses an empty list, so an emptied key leaves the policy entirely.
  if (caps.size === 0) delete keys[key];
  else keys[key] = CAPABILITIES.filter((k) => caps.has(k));
  if (Object.keys(keys).length === 0) delete p.keys;
  return next;
}

export function setAdmin(c: Config, policy: string, cap: AdminCapability, on: boolean): Config {
  const next = copy(c);
  const p = (next.policies[policy] ??= {});
  const caps = new Set(p.admin ?? []);
  if (on) caps.add(cap);
  else caps.delete(cap);
  // An explicit `admin: []` is refused; none means leaving the field out.
  if (caps.size === 0) delete p.admin;
  else p.admin = ADMIN_CAPABILITIES.filter((k) => caps.has(k));
  return next;
}

/** Every key in the config, with the capabilities `policy` grants on it (possibly none). */
export function capabilityGrid(c: Config, policy: string): Record<string, Set<Capability>> {
  const granted = c.policies[policy]?.keys ?? {};
  const grid: Record<string, Set<Capability>> = {};
  for (const key of Object.keys(c.keys)) grid[key] = new Set(granted[key] ?? []);
  return grid;
}
