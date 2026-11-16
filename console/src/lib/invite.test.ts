import { describe, expect, it } from "vitest";
import { checkNote, MAX_NOTE_BYTES, MAX_NOTE_CHARS, noteLength } from "./invite";

// The same cases as edgekms-core's `invite_notes_follow_the_rules`: the control plane decides,
// and the page only warns early with the server's own words.
describe("checkNote", () => {
  it("allows an empty note and plain text with line breaks", () => {
    expect(checkNote("")).toBeNull();
    expect(checkNote("   \n\t ")).toBeNull();
    expect(checkNote("line one\nline two")).toBeNull();
    expect(checkNote("café 🔐")).toBeNull();
  });

  it("refuses control characters other than a line break", () => {
    for (const bad of ["a\rb", "a\tb", "a\u001b[31mb", "a\u0000b", "a\u007fb", "a\u0085b", "a\u009bb"]) {
      expect(checkNote(bad)).toBe(
        "the note can't contain control characters other than line breaks",
      );
    }
  });

  it("refuses bidirectional formatting characters", () => {
    for (const bad of ["a‮b", "a‪b", "a⁦b", "a⁩b", "a‎b", "a‏b", "a؜b"]) {
      expect(checkNote(bad)).toBe("the note can't contain bidirectional formatting characters");
    }
  });

  it("refuses invisible characters but keeps zero-width joiners", () => {
    for (const bad of ["a\u200bb", "a\ufeffb", "\ufeffa", "a\u2028b", "a\u2060b", "a\u00adb", "a\u{e0041}b"]) {
      expect(checkNote(bad)).toBe("the note can't contain invisible characters");
    }
    expect(checkNote("\u{1f469}\u200d\u{1f4bb}")).toBeNull();
  });

  it("counts characters, not UTF-16 units, after trimming", () => {
    expect(checkNote("a".repeat(MAX_NOTE_CHARS))).toBeNull();
    expect(checkNote("a".repeat(MAX_NOTE_CHARS + 1))).toBe(
      "the note must be at most 500 characters",
    );
    expect(checkNote(`  ${"a".repeat(MAX_NOTE_CHARS)}\n `)).toBeNull();
    // 500 four-byte characters: 1000 UTF-16 units, 2000 bytes, and allowed.
    expect(checkNote("🔐".repeat(MAX_NOTE_CHARS))).toBeNull();
    expect(checkNote("a".repeat(MAX_NOTE_BYTES + 1))).toBe("the note must be at most 2000 bytes");
  });
});

describe("noteLength", () => {
  it("is the trimmed note's characters", () => {
    expect(noteLength("")).toBe(0);
    expect(noteLength("  ab \n")).toBe(2);
    expect(noteLength("🔐🔐")).toBe(2);
  });
});
