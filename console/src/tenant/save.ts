import { ApiError, request, tenantPath } from "../lib/api";
import type { Config } from "../lib/config";

export type SaveResult =
  | { ok: true; version: number }
  | { ok: false; conflict: true }
  | { ok: false; message: string; reauth?: true };

/** Saves the whole config, guarded by the version it was read at. */
export async function saveConfig(name: string, config: Config, version: number): Promise<SaveResult> {
  try {
    const data = await request<{ config_version?: number } | undefined>(
      "PUT",
      `${tenantPath(name)}/config`,
      { body: config, ifMatch: version },
    );
    return { ok: true, version: data?.config_version ?? version + 1 };
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 409) return { ok: false, conflict: true };
      if (e.reauth) return { ok: false, message: "Your session ended. Taking you to sign in.", reauth: true };
      return { ok: false, message: e.message };
    }
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}
