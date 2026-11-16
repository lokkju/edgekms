import type { Config } from "../lib/config";

/** The typed confirmation for an export: the exact tenant name, case and all. */
export function confirmMatches(typed: string, name: string): boolean {
  return name !== "" && typed === name;
}

/**
 * The tenant's config as a file to keep with an exported root key: offline decrypt needs the
 * key ids it holds. The config has the root id but never the root key.
 */
export function configFile(name: string, config: Config): { filename: string; text: string } {
  return { filename: `${name}-config.json`, text: JSON.stringify(config, null, 2) + "\n" };
}

/** Where a fresh sign-in returns to before the export can proceed. */
export function exportReturnPath(name: string): string {
  return `/t/${encodeURIComponent(name)}/export`;
}
