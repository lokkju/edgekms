// A small History-API router. Paths under /auth/ and /api/ belong to the Worker and are never
// routed here: links to them are real navigations.

import { writable, type Readable } from "svelte/store";

export type RouteName = "home" | "signin" | "request-invite" | "tenant" | "ops" | "account" | "notfound";

export interface Route {
  name: RouteName;
  params: Record<string, string>;
}

const PATTERNS: [RouteName, string[]][] = [
  ["home", []],
  ["signin", ["signin"]],
  ["request-invite", ["request-invite"]],
  ["ops", ["ops"]],
  ["account", ["account"]],
  ["tenant", ["t", ":name"]],
  ["tenant", ["t", ":name", ":tab"]],
];

const NOT_FOUND: Route = { name: "notfound", params: {} };

export function match(path: string): Route {
  const trimmed = path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
  if (!trimmed.startsWith("/")) return NOT_FOUND;
  const parts = trimmed === "/" ? [] : trimmed.slice(1).split("/");
  for (const [name, pattern] of PATTERNS) {
    if (pattern.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < pattern.length; i++) {
      const want = pattern[i] as string;
      const got = parts[i] as string;
      if (want.startsWith(":")) {
        let value: string;
        try {
          value = decodeURIComponent(got);
        } catch {
          return NOT_FOUND;
        }
        if (value === "") {
          ok = false;
          break;
        }
        params[want.slice(1)] = value;
      } else if (want !== got) {
        ok = false;
        break;
      }
    }
    if (ok) return { name, params };
  }
  return NOT_FOUND;
}

const store = writable<Route>(
  typeof location === "undefined" ? { name: "home", params: {} } : match(location.pathname),
);

export const route: Readable<Route> = { subscribe: store.subscribe };

export function navigate(path: string, replace = false): void {
  if (replace) history.replaceState(null, "", path);
  else history.pushState(null, "", path);
  store.set(match(location.pathname));
  window.scrollTo(0, 0);
}

/** Starts listening for back/forward and for clicks on same-origin links. */
export function startRouter(): () => void {
  const onPop = () => store.set(match(location.pathname));
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    const a = (e.target as Element | null)?.closest?.("a");
    if (!a || a.target || a.hasAttribute("download")) return;
    const url = new URL(a.href, location.href);
    if (url.origin !== location.origin) return;
    if (url.pathname.startsWith("/auth/") || url.pathname.startsWith("/api/")) return;
    e.preventDefault();
    navigate(url.pathname + url.search);
  };
  window.addEventListener("popstate", onPop);
  document.addEventListener("click", onClick);
  store.set(match(location.pathname));
  return () => {
    window.removeEventListener("popstate", onPop);
    document.removeEventListener("click", onClick);
  };
}
