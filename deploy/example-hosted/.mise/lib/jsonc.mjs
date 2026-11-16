// Prints the JSONC file named by argv[2] as plain JSON on stdout: strips // and /* */ comments,
// then trailing commas, leaving string contents alone. Enough for wrangler.jsonc, so the tasks
// can check it with jq; anything it can't turn into valid JSON fails JSON.parse and exits non-zero.
import { readFileSync } from "node:fs";

// Calls f(char, index) for every character outside a string; characters inside strings (and the
// quotes) are copied as they are.
function scan(src, f) {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    if (src[i] === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      if (j >= src.length) throw new Error("unterminated string");
      out += src.slice(i, j + 1);
      i = j;
    } else {
      const r = f(src[i], i);
      out += r.text;
      i += r.skip;
    }
  }
  return out;
}

const src = readFileSync(process.argv[2], "utf8");
const noComments = scan(src, (c, i) => {
  if (c === "/" && src[i + 1] === "/") {
    const nl = src.indexOf("\n", i);
    return { text: "\n", skip: (nl < 0 ? src.length : nl) - i };
  }
  if (c === "/" && src[i + 1] === "*") {
    const end = src.indexOf("*/", i + 2);
    if (end < 0) throw new Error("unterminated block comment");
    return { text: " ", skip: end + 1 - i };
  }
  return { text: c, skip: 0 };
});
const noTrailing = scan(noComments, (c, i) => {
  if (c === ",") {
    const next = noComments.slice(i + 1).match(/\S/);
    if (next && (next[0] === "}" || next[0] === "]")) return { text: "", skip: 0 };
  }
  return { text: c, skip: 0 };
});
process.stdout.write(JSON.stringify(JSON.parse(noTrailing)) + "\n");
