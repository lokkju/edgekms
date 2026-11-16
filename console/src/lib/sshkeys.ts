// SSH public keys for the Account page: parsing a pasted key, its fingerprint (the one
// `ssh-keygen -lf` prints), key ids, the label rules mirrored from the control plane, the
// registration signing command and which keys a key added. The control plane decides every rule;
// these exist so the page can say what's wrong before sending.

import type { SshKey } from "./api";

export type { SshKey };

export const KEY_TYPES = [
  "ssh-ed25519",
  "sk-ssh-ed25519@openssh.com",
  "ecdsa-sha2-nistp256",
] as const;

export type KeyType = (typeof KEY_TYPES)[number];

/** The control plane's limit on a pasted public key line. */
export const MAX_PUBLIC_KEY_BYTES = 8192;

export const MAX_LABEL_CHARS = 64;

/** The namespace a registration proof is signed with; a login uses `edgekms`. */
export const REGISTER_NAMESPACE = "edgekms-register";

export interface ParsedKey {
  keyType: KeyType;
  /** The decoded key blob, what the fingerprint hashes. */
  blob: Uint8Array<ArrayBuffer>;
  /** `<type> <base64>`, without the comment, as the control plane stores it. */
  publicKey: string;
  comment: string;
}

export type ParseResult =
  | { ok: true; key: ParsedKey }
  | { ok: false; error: "ssh_key_invalid" | "ssh_key_unsupported" };

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
/** What an SSH algorithm name looks like, to tell an unsupported key from text that isn't one. */
const ALGORITHM = /^[a-z0-9][a-z0-9.@-]*$/;

function decodeBase64(b64: string): Uint8Array<ArrayBuffer> | null {
  if (!BASE64.test(b64) || b64.length % 4 !== 0) return null;
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Reads the SSH wire format's length-prefixed strings off a blob. */
class Reader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  string(): Uint8Array | null {
    if (this.pos + 4 > this.buf.length) return null;
    const b = this.buf;
    const len = ((b[this.pos]! << 24) | (b[this.pos + 1]! << 16) | (b[this.pos + 2]! << 8) | b[this.pos + 3]!) >>> 0;
    this.pos += 4;
    if (this.pos + len > b.length) return null;
    const s = b.subarray(this.pos, this.pos + len);
    this.pos += len;
    return s;
  }

  done(): boolean {
    return this.pos === this.buf.length;
  }
}

const text = (b: Uint8Array | null): string | null =>
  b === null ? null : new TextDecoder().decode(b);

/** Whether `blob` is a well-formed key of `type`, with nothing left over. */
function blobMatches(type: KeyType, blob: Uint8Array): boolean {
  const r = new Reader(blob);
  if (text(r.string()) !== type) return false;
  switch (type) {
    case "ssh-ed25519":
      if (r.string()?.length !== 32) return false;
      break;
    case "sk-ssh-ed25519@openssh.com":
      if (r.string()?.length !== 32) return false;
      if (r.string() === null) return false;
      break;
    case "ecdsa-sha2-nistp256": {
      if (text(r.string()) !== "nistp256") return false;
      const q = r.string();
      if (q?.length !== 65 || q[0] !== 0x04) return false;
      break;
    }
  }
  return r.done();
}

/** One OpenSSH public key line, as `ssh-keygen` writes a `.pub` file. */
export function parsePublicKey(input: string): ParseResult {
  const invalid = { ok: false, error: "ssh_key_invalid" } as const;
  const line = input.trim();
  if (line === "" || /[\r\n]/.test(line)) return invalid;
  if (new TextEncoder().encode(line).length > MAX_PUBLIC_KEY_BYTES) return invalid;
  const m = /^(\S+)\s+(\S+)(?:\s+([\s\S]*))?$/.exec(line);
  if (!m) return invalid;
  const [, type = "", b64 = "", comment = ""] = m;
  const blob = decodeBase64(b64);
  if (blob === null || !ALGORITHM.test(type)) return invalid;
  if (!(KEY_TYPES as readonly string[]).includes(type)) {
    return { ok: false, error: "ssh_key_unsupported" };
  }
  const keyType = type as KeyType;
  if (!blobMatches(keyType, blob)) return invalid;
  return { ok: true, key: { keyType, blob, publicKey: `${type} ${b64}`, comment: comment.trim() } };
}

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** `SHA256:` and the unpadded base64 of the blob's SHA-256, as `ssh-keygen -lf` prints it. */
export async function fingerprint(blob: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return "SHA256:" + toBase64(digest).replace(/=+$/, "");
}

/** The fingerprint cut to its first 8 characters of hash, for naming a key in a sentence. */
export function shortFingerprint(fp: string): string {
  return fp.startsWith("SHA256:") ? fp.slice(0, "SHA256:".length + 8) : fp;
}

const FP_B64 = /^[A-Za-z0-9+/]{43}$/;
const ID = /^[A-Za-z0-9_-]{43}$/;

/** A key's id in routes: the fingerprint's base64 in base64url, 43 characters. */
export function keyId(fp: string): string | null {
  if (!fp.startsWith("SHA256:")) return null;
  const b64 = fp.slice("SHA256:".length);
  if (!FP_B64.test(b64)) return null;
  return b64.replace(/\+/g, "-").replace(/\//g, "_");
}

export function fingerprintFromId(id: string): string | null {
  if (!ID.test(id)) return null;
  return "SHA256:" + id.replace(/-/g, "+").replace(/_/g, "/");
}

/** Bidirectional formatting characters: embeddings, overrides, isolates and the three marks. */
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

/** Invisible text: the soft hyphen, zero-width space, word joiner, BOM, line and paragraph
 * separators, and the tag characters. Zero-width joiners stay allowed. */
const INVISIBLE = /[\u00ad\u200b\u2060\u2028\u2029\ufeff\u{e0000}-\u{e007f}]/u;

/** C0 controls, DEL and C1 controls: Rust's `char::is_control`. */
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

/** Trims Unicode White_Space only, as Rust's `str::trim` does (JS `trim` also strips U+FEFF). */
const trimRust = (s: string): string => s.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");

export type LabelResult = { ok: true; label: string } | { ok: false; reason: string };

/** A key's label as the control plane would store it, or the rule it breaks. Empty is fine. */
export function checkLabel(raw: string): LabelResult {
  const label = trimRust(raw);
  if ([...label].length > MAX_LABEL_CHARS) {
    return { ok: false, reason: `the label must be at most ${MAX_LABEL_CHARS} characters` };
  }
  if (CONTROL.test(label)) return { ok: false, reason: "the label can't contain control characters" };
  if (BIDI.test(label)) {
    return { ok: false, reason: "the label can't contain bidirectional formatting characters" };
  }
  if (INVISIBLE.test(label)) return { ok: false, reason: "the label can't contain invisible characters" };
  return { ok: true, label };
}

/** The label a pasted key starts with: its comment, when the comment passes the label rules. */
export function defaultLabel(comment: string): string {
  const r = checkLabel(comment);
  return r.ok ? r.label : "";
}

/** `s` in single quotes for a POSIX shell, each `'` closed, escaped and reopened. */
const shellQuote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

/** The account a registration challenge registers a key to. */
export interface RegisterAccount {
  githubId: number;
  login: string;
}

/**
 * `ekmsr.<github_id>.<login>.<tail>`: the id in decimal without leading zeros, the login a GitHub
 * login's shape (1 to 39 letters, digits and hyphens), then something after the last dot. The
 * control plane checks the MAC; this only reads the account, as the core parser does.
 */
const REGISTER_CHALLENGE = /^ekmsr\.(0|[1-9][0-9]{0,19})\.([A-Za-z0-9-]{1,39})\.(.+)$/s;

/** The account a registration challenge names, or null for anything that isn't one. */
export function registerAccount(challenge: string): RegisterAccount | null {
  const m = REGISTER_CHALLENGE.exec(challenge);
  if (!m) return null;
  const id = Number(m[1]);
  if (!Number.isSafeInteger(id)) return null;
  return { githubId: id, login: m[2] ?? "" };
}

/** The sentence the signing command prints, naming the account the key goes to. */
export function accountSentence(a: RegisterAccount): string {
  return `Registering this key to GitHub account ${a.login} (${a.githubId})`;
}

/**
 * The command that signs a registration challenge with the key being added. It first prints, on
 * stderr, the account the challenge registers the key to (the same account leads the signed
 * text), so whoever runs it sees whose account it is. `printf '%s'` and not `echo`: a trailing
 * newline would change what is signed. The preamble is a command, not a `#` comment, since zsh
 * takes a `#` line typed at its prompt for a command unless `interactive_comments` is set.
 */
export function signingCommand(challenge: string, keyPath = "~/.ssh/YOUR_KEY.pub"): string {
  if (challenge === "" || CONTROL.test(challenge)) {
    throw new Error("the challenge isn't printable text");
  }
  const account = registerAccount(challenge);
  if (account === null) throw new Error("the challenge doesn't name an account");
  return (
    `printf '%s\\n' ${shellQuote(accountSentence(account))} >&2; ` +
    `printf '%s' ${shellQuote(challenge)} | ssh-keygen -Y sign -n ${REGISTER_NAMESPACE} -f ${keyPath}`
  );
}

/** The keys whose session `key` added: their `added_via` is `ssh:<key's fingerprint>`. */
export function addedBy(keys: readonly SshKey[], key: SshKey): SshKey[] {
  const via = `ssh:${key.fingerprint}`;
  return keys.filter((k) => k.added_via === via);
}

/** A key named in a sentence: its label, or its short fingerprint without one. */
export function keyName(key: Pick<SshKey, "label" | "fingerprint">): string {
  return key.label !== "" ? key.label : shortFingerprint(key.fingerprint);
}

/** Where `key` came from, in words: the GitHub login or the SSH key behind its session. */
export function lineage(key: SshKey, keys: readonly SshKey[]): string {
  if (key.added_via === "github") return "added from a GitHub login";
  if (key.added_via.startsWith("ssh:")) {
    const fp = key.added_via.slice("ssh:".length);
    const parent = keys.find((k) => k.fingerprint === fp);
    return `added from SSH key ${parent ? keyName(parent) : shortFingerprint(fp)}`;
  }
  return `added via ${key.added_via}`;
}

/** Whether every signature by a key of this type needs a touch: only security keys. */
export function needsTouch(type: string): boolean {
  return type === "sk-ssh-ed25519@openssh.com";
}

/** One sentence for each refusal of `POST /me/ssh-keys` the page explains itself. */
const ADD_ERRORS: Record<string, string> = {
  ssh_key_proof_failed:
    "The signature didn't match this key and challenge: get a new signing command and try again.",
  ssh_key_in_use: "That key is already registered to an edgekms account, this one or another.",
  ssh_key_limit: "Your account has 10 SSH keys, the most it can hold; remove one to add another.",
  label_invalid:
    "The label must be at most 64 characters, with no control, bidirectional formatting or invisible characters.",
  ssh_key_invalid:
    "That isn't an OpenSSH public key line; paste the whole contents of the key's .pub file.",
  ssh_key_unsupported:
    "edgekms takes ssh-ed25519, sk-ssh-ed25519@openssh.com and ecdsa-sha2-nistp256 keys; RSA and other types can't log in.",
};

export function addErrorMessage(code: string | undefined): string | null {
  return code !== undefined && Object.hasOwn(ADD_ERRORS, code) ? (ADD_ERRORS[code] ?? null) : null;
}

/** The sessionStorage entry that keeps the add form across a fresh sign-in. */
export const DRAFT_KEY = "edgekms.ssh-key-draft";

/** What survives the sign-in detour: a public key and a label, nothing secret. */
export interface Draft {
  public_key: string;
  label: string;
}

type DraftStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

export function saveDraft(storage: DraftStorage, draft: Draft): void {
  const only: Draft = { public_key: draft.public_key, label: draft.label };
  try {
    storage.setItem(DRAFT_KEY, JSON.stringify(only));
  } catch {
    // Storage refused (private mode, quota): the form just won't come back filled in.
  }
}

/** The saved draft, removed as it's read, or null without a well-formed one. */
export function takeDraft(storage: DraftStorage): Draft | null {
  let raw: string | null;
  try {
    raw = storage.getItem(DRAFT_KEY);
    storage.removeItem(DRAFT_KEY);
  } catch {
    return null;
  }
  if (raw === null) return null;
  try {
    const v: unknown = JSON.parse(raw);
    if (v && typeof v === "object") {
      const { public_key, label } = v as { public_key?: unknown; label?: unknown };
      if (typeof public_key === "string" && typeof label === "string") return { public_key, label };
    }
  } catch {
    // Not JSON.
  }
  return null;
}

/** Milliseconds left as `m:ss`, rounded up, never below `0:00`. */
export function countdown(ms: number): string {
  const secs = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}
