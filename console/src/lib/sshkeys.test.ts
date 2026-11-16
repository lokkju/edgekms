import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  addErrorMessage,
  addedBy,
  checkLabel,
  countdown,
  DRAFT_KEY,
  defaultLabel,
  fingerprint,
  fingerprintFromId,
  keyId,
  lineage,
  needsTouch,
  parsePublicKey,
  registerAccount,
  saveDraft,
  shortFingerprint,
  signingCommand,
  takeDraft,
  type SshKey,
} from "./sshkeys";

// Fixture keys made with ssh-keygen; each fingerprint is what `ssh-keygen -lf` printed for it.
// The sk key was assembled by hand (no security key needed to fingerprint a public key).
const ED25519 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDkBO98B+KFd8sDdoOSJYGv7EL8kIm1Stu7PdZzX3CXG nick@laptop";
const ED25519_FP = "SHA256:EElDPqD3VfhASD1R+/l1pnDKkILTpdfv5Fp4xMVYZXE";
const ECDSA =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJO4kQb9ilcQAbuq9tdm0VJKzxkqBn/Imeqta7mcVNcIVCox1jqV6I92fZILz89Pjn0yCUwv6jPjd72SdE7SOjA= work ecdsa";
const ECDSA_FP = "SHA256:0kvU8VadKghlGEtpRk1TuZzWHU2DRhgHfXE5CX+qVSk";
const SK =
  "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyucDHztXcAAAABHNzaDo= yubikey-5c";
const SK_FP = "SHA256:83ny0sBD6XvpUfb31f8h4vb4GZRmF5WvKEmNe8GtLQU";
const RSA =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCgYECLtxsDPdkYvnyGkzi+1qVqsYMXZZd61oYDN1vtPzx61PuGWJCvQ5PMU2v3yh4yVGt1g4aPKlwW605lpxY2Yqw4m1f5xQPaQuwub3ecmDS+vpVWBFRqpg0HjxYJr8GpvcA1pz7DJHGqOqD0bQG9pjCjMXMMA8i5xNx0JAvfdQ== rsa";

function parsed(line: string) {
  const r = parsePublicKey(line);
  if (!r.ok) throw new Error(`expected ${line} to parse, got ${r.error}`);
  return r.key;
}

describe("parsePublicKey", () => {
  it("parses each supported type, keeping the comment apart", () => {
    const ed = parsed(ED25519);
    expect(ed.keyType).toBe("ssh-ed25519");
    expect(ed.comment).toBe("nick@laptop");
    expect(ed.publicKey).toBe(ED25519.split(" ").slice(0, 2).join(" "));
    expect(parsed(ECDSA).keyType).toBe("ecdsa-sha2-nistp256");
    expect(parsed(ECDSA).comment).toBe("work ecdsa");
    expect(parsed(SK).keyType).toBe("sk-ssh-ed25519@openssh.com");
  });

  it("accepts surrounding whitespace, one trailing newline and no comment", () => {
    expect(parsed(`  ${ED25519}\n`).comment).toBe("nick@laptop");
    expect(parsed(ED25519.split(" ").slice(0, 2).join(" ")).comment).toBe("");
  });

  it("refuses RSA and other types as unsupported", () => {
    expect(parsePublicKey(RSA)).toEqual({ ok: false, error: "ssh_key_unsupported" });
    expect(parsePublicKey("sk-ecdsa-sha2-nistp256@openssh.com AAAA")).toEqual({
      ok: false,
      error: "ssh_key_unsupported",
    });
  });

  it("refuses what isn't one public key line as invalid", () => {
    for (const bad of [
      "",
      "   ",
      "ssh-ed25519",
      "ssh-ed25519 not*base64",
      "ssh-ed25519 AAAA",
      `${ED25519}\n${ECDSA}`,
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      // The blob names another type than the line does.
      `ssh-ed25519 ${ECDSA.split(" ")[1]}`,
      // A truncated blob.
      `ssh-ed25519 ${ED25519.split(" ")[1]?.slice(0, 40)}`,
      // Longer than the control plane's 8 KiB.
      `${ED25519} ${"x".repeat(8192)}`,
    ]) {
      expect(parsePublicKey(bad), JSON.stringify(bad)).toEqual({ ok: false, error: "ssh_key_invalid" });
    }
  });
});

describe("fingerprint", () => {
  it("matches ssh-keygen -lf for each fixture key", async () => {
    expect(await fingerprint(parsed(ED25519).blob)).toBe(ED25519_FP);
    expect(await fingerprint(parsed(ECDSA).blob)).toBe(ECDSA_FP);
    expect(await fingerprint(parsed(SK).blob)).toBe(SK_FP);
  });

  it("shortens to the first characters after SHA256:", () => {
    expect(shortFingerprint(ED25519_FP)).toBe("SHA256:EElDPqD3");
  });
});

describe("key ids", () => {
  it("map a fingerprint's base64 to base64url and back", () => {
    const id = keyId(ED25519_FP);
    expect(id).toBe("EElDPqD3VfhASD1R-_l1pnDKkILTpdfv5Fp4xMVYZXE");
    expect(id).toHaveLength(43);
    expect(fingerprintFromId(id as string)).toBe(ED25519_FP);
    for (const fp of [ECDSA_FP, SK_FP]) {
      expect(fingerprintFromId(keyId(fp) as string)).toBe(fp);
    }
  });

  it("refuse malformed input", () => {
    expect(keyId("MD5:aa:bb")).toBeNull();
    expect(keyId("SHA256:short")).toBeNull();
    expect(keyId(`SHA256:${"A".repeat(42)}=`)).toBeNull();
    expect(fingerprintFromId("A".repeat(42))).toBeNull();
    expect(fingerprintFromId(`${"A".repeat(42)}+`)).toBeNull();
    expect(fingerprintFromId(`${"A".repeat(42)}/`)).toBeNull();
  });
});

describe("checkLabel", () => {
  it("trims, and allows empty", () => {
    expect(checkLabel("  laptop \t")).toEqual({ ok: true, label: "laptop" });
    expect(checkLabel("")).toEqual({ ok: true, label: "" });
  });

  it("counts 64 characters as code points", () => {
    expect(checkLabel("\u00e9".repeat(64))).toEqual({ ok: true, label: "\u00e9".repeat(64) });
    expect(checkLabel("\u{1f511}".repeat(64)).ok).toBe(true);
    expect(checkLabel("a".repeat(65))).toEqual({
      ok: false,
      reason: "the label must be at most 64 characters",
    });
  });

  it("refuses control characters", () => {
    for (const bad of ["a\nb", "a\tb", "a\u0000b", "a\u007fb", "a\u0085b"]) {
      expect(checkLabel(bad)).toEqual({ ok: false, reason: "the label can't contain control characters" });
    }
  });

  it("refuses bidirectional formatting characters", () => {
    for (const c of ["\u061c", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069"]) {
      expect(checkLabel(`a${c}b`)).toEqual({
        ok: false,
        reason: "the label can't contain bidirectional formatting characters",
      });
    }
  });

  it("refuses invisible characters but keeps zero-width joiners", () => {
    for (const c of ["\u00ad", "\u200b", "\u2060", "\u2028", "\u2029", "\ufeff", "\u{e0001}", "\u{e007f}"]) {
      expect(checkLabel(`a${c}b`), c.codePointAt(0)?.toString(16)).toEqual({
        ok: false,
        reason: "the label can't contain invisible characters",
      });
    }
    // A trailing BOM isn't whitespace to the control plane, so it isn't trimmed here either.
    expect(checkLabel("laptop\ufeff").ok).toBe(false);
    expect(checkLabel("\u{1f469}\u200d\u{1f4bb}").ok).toBe(true);
  });
});

describe("defaultLabel", () => {
  it("is the comment when the comment passes, else empty", () => {
    expect(defaultLabel("nick@laptop")).toBe("nick@laptop");
    expect(defaultLabel("  spaced  ")).toBe("spaced");
    expect(defaultLabel("a".repeat(65))).toBe("");
    expect(defaultLabel("evil\u202ename")).toBe("");
    expect(defaultLabel("")).toBe("");
  });
});

describe("registerAccount", () => {
  it("reads the account a registration challenge names", () => {
    expect(registerAccount("ekmsr.42.alice.AAAA_-")).toEqual({ githubId: 42, login: "alice" });
    expect(registerAccount("ekmsr.583231.octo-cat.AAAA")).toEqual({ githubId: 583231, login: "octo-cat" });
  });

  it("refuses anything else", () => {
    for (const bad of [
      "ekmsc.AAAA",
      "ekmsr.42.alice",
      "ekmsr.42.alice.",
      "ekmsr.042.alice.AAAA",
      "ekmsr.-1.alice.AAAA",
      "ekmsr.99999999999999999999.alice.AAAA",
      "ekmsr.42.al ice.AAAA",
      "ekmsr.42.al'ice.AAAA",
      `ekmsr.42.${"x".repeat(40)}.AAAA`,
      "ekmsr..alice.AAAA",
      "",
    ]) {
      expect(registerAccount(bad), bad).toBeNull();
    }
  });
});

describe("signingCommand", () => {
  const challenge = "ekmsr.42.alice.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA_-";
  const said = "Registering this key to GitHub account alice (42)";

  it("names the account, then pipes the challenge through printf '%s' into ssh-keygen", () => {
    expect(signingCommand(challenge)).toBe(
      `printf '%s\\n' '${said}' >&2; ` +
        `printf '%s' '${challenge}' | ssh-keygen -Y sign -n edgekms-register -f ~/.ssh/YOUR_KEY.pub`,
    );
  });

  it("prints the account on stderr and the challenge on stdout, byte for byte", () => {
    for (const odd of ["AAAA", "it's", "'''", "a b $HOME `id` \\ \"q\"", "%s%d"]) {
      const c = `ekmsr.42.alice.${odd}`;
      const cmd = signingCommand(c);
      const printf = cmd.slice(0, cmd.indexOf(" | ssh-keygen"));
      expect(execFileSync("sh", ["-c", `${printf} 2>/dev/null`], { encoding: "utf8" })).toBe(c);
      expect(execFileSync("sh", ["-c", `{ ${printf}; } 2>&1 >/dev/null`], { encoding: "utf8" })).toBe(
        `${said}\n`,
      );
    }
  });

  it("refuses a challenge that names no account, or has control characters", () => {
    expect(() => signingCommand("ekmsc.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA_-")).toThrow();
    expect(() => signingCommand("ekmsr.42.alice.a\nrm -rf ~")).toThrow();
    expect(() => signingCommand("")).toThrow();
  });
});

describe("lineage", () => {
  const key = (fingerprint: string, added_via: string, label = ""): SshKey => ({
    id: keyId(fingerprint) as string,
    fingerprint,
    key_type: "ssh-ed25519",
    public_key: "ssh-ed25519 AAAA",
    label,
    added_ms: 1_794_355_200_000,
    added_via,
    last_used_ms: null,
  });
  const a = key(ED25519_FP, "github", "laptop");
  const b = key(ECDSA_FP, `ssh:${ED25519_FP}`);
  const c = key(SK_FP, `ssh:${ED25519_FP}`, "yubikey");
  const keys = [a, b, c];

  it("finds the keys a key added", () => {
    expect(addedBy(keys, a)).toEqual([b, c]);
    expect(addedBy(keys, b)).toEqual([]);
  });

  it("describes where a key came from", () => {
    expect(lineage(a, keys)).toBe("added from a GitHub login");
    expect(lineage(b, keys)).toBe("added from SSH key laptop");
    const orphan = key(SK_FP, `ssh:${ECDSA_FP}`);
    expect(lineage(orphan, [orphan])).toBe("added from SSH key SHA256:0kvU8Vad");
    // A parent with no label is named by its short fingerprint too.
    expect(lineage(orphan, [orphan, b])).toBe("added from SSH key SHA256:0kvU8Vad");
  });
});

describe("needsTouch", () => {
  it("is true only for security keys", () => {
    expect(needsTouch("sk-ssh-ed25519@openssh.com")).toBe(true);
    expect(needsTouch("ssh-ed25519")).toBe(false);
    expect(needsTouch("ecdsa-sha2-nistp256")).toBe(false);
  });
});

describe("addErrorMessage", () => {
  it("has one sentence for each refusal code of the add", () => {
    for (const code of [
      "ssh_key_proof_failed",
      "ssh_key_in_use",
      "ssh_key_limit",
      "label_invalid",
      "ssh_key_invalid",
      "ssh_key_unsupported",
    ]) {
      const m = addErrorMessage(code);
      expect(m, code).not.toBeNull();
      expect(m?.endsWith("."), code).toBe(true);
    }
    expect(addErrorMessage("ssh_key_proof_failed")).toContain("get a new signing command");
    expect(addErrorMessage("ssh_key_limit")).toContain("10");
    expect(addErrorMessage("something_else")).toBeNull();
    expect(addErrorMessage(undefined)).toBeNull();
  });
});

describe("drafts", () => {
  class Mem {
    items = new Map<string, string>();
    getItem(k: string) {
      return this.items.get(k) ?? null;
    }
    setItem(k: string, v: string) {
      this.items.set(k, v);
    }
    removeItem(k: string) {
      this.items.delete(k);
    }
  }

  it("keep only the public key and label, and are read once", () => {
    const s = new Mem();
    saveDraft(s, { public_key: ED25519, label: "laptop" });
    expect([...s.items.keys()]).toEqual([DRAFT_KEY]);
    expect(JSON.parse(s.items.get(DRAFT_KEY) as string)).toEqual({
      public_key: ED25519,
      label: "laptop",
    });
    expect(takeDraft(s)).toEqual({ public_key: ED25519, label: "laptop" });
    expect(takeDraft(s)).toBeNull();
  });

  it("never store more than the public key and label", () => {
    const s = new Mem();
    const extra = { public_key: "k", label: "x", challenge: "c", signature: "s" };
    saveDraft(s, extra);
    expect(JSON.parse(s.items.get(DRAFT_KEY) as string)).toEqual({ public_key: "k", label: "x" });
  });

  it("ignore anything that isn't a draft", () => {
    const s = new Mem();
    s.setItem(DRAFT_KEY, "not json");
    expect(takeDraft(s)).toBeNull();
    s.setItem(DRAFT_KEY, JSON.stringify({ public_key: 1, label: "x" }));
    expect(takeDraft(s)).toBeNull();
    s.setItem(DRAFT_KEY, JSON.stringify({ public_key: "k", label: "x", challenge: "c" }));
    expect(takeDraft(s)).toEqual({ public_key: "k", label: "x" });
  });

  it("survive storage that throws", () => {
    const denied = () => {
      throw new Error("denied");
    };
    const broken = { getItem: denied, setItem: denied, removeItem: denied };
    expect(() => saveDraft(broken, { public_key: "k", label: "" })).not.toThrow();
    expect(takeDraft(broken)).toBeNull();
  });
});

describe("countdown", () => {
  it("formats the time left as m:ss and stops at zero", () => {
    expect(countdown(300_000)).toBe("5:00");
    expect(countdown(61_500)).toBe("1:02");
    expect(countdown(999)).toBe("0:01");
    expect(countdown(0)).toBe("0:00");
    expect(countdown(-5)).toBe("0:00");
  });
});
