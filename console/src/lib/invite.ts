// The invite request note's rules, mirrored from the control plane (edgekms-core's
// `hosted::invite_note`) so the page can say what's wrong before sending. The control plane
// decides; the messages are its own, word for word.

export const MAX_NOTE_CHARS = 500;
export const MAX_NOTE_BYTES = 2000;

/** Bidirectional formatting characters: embeddings, overrides, isolates and the three marks. */
const BIDI = /[؜‎‏‪-‮⁦-⁩]/u;

/** Invisible text: the soft hyphen, zero-width space, word joiner, BOM, line and paragraph
 * separators, and the tag characters. Zero-width joiners stay allowed. */
const INVISIBLE = /[\u00ad\u200b\u2060\u2028\u2029\ufeff\u{e0000}-\u{e007f}]/u;

/** Trims Unicode White_Space only, as Rust's `str::trim` does (JS `trim` also strips U+FEFF). */
const trimRust = (s: string): string => s.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");

/** C0 controls but the line break, DEL, and C1 controls. */
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u;

/** The note's length in characters (code points) once trimmed, as the control plane counts it. */
export function noteLength(note: string): number {
  return [...trimRust(note)].length;
}

/** The rule `note` breaks, in the control plane's words, or null when it's fine. */
export function checkNote(note: string): string | null {
  const trimmed = trimRust(note);
  if (new TextEncoder().encode(trimmed).length > MAX_NOTE_BYTES) {
    return "the note must be at most 2000 bytes";
  }
  if ([...trimmed].length > MAX_NOTE_CHARS) return "the note must be at most 500 characters";
  if (CONTROL.test(trimmed)) {
    return "the note can't contain control characters other than line breaks";
  }
  if (BIDI.test(trimmed)) return "the note can't contain bidirectional formatting characters";
  if (INVISIBLE.test(trimmed)) return "the note can't contain invisible characters";
  return null;
}

/** `ms` as a UTC calendar date, `YYYY-MM-DD`. */
export const utcDate = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
