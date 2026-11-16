<script lang="ts">
  import { onDestroy } from "svelte";
  import { ApiError, request, signIn, tenantPath, type Exported } from "../lib/api";
  import Help from "../lib/Help.svelte";
  import type { Config } from "../lib/config";
  import { configFile, confirmMatches, exportReturnPath } from "./export";

  let { name, config }: { name: string; config: Config } = $props();

  let typed = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let copied = $state(false);
  // The root key lives only here, for as long as this view is open. Never in a store, the URL or
  // browser storage.
  let result = $state<Exported | null>(null);

  onDestroy(() => {
    result = null;
  });

  const ready = $derived(confirmMatches(typed, name));

  async function doExport(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!ready) return;
    busy = true;
    error = null;
    try {
      result = await request<Exported>("POST", `${tenantPath(name)}/export`, { body: {} });
      typed = "";
    } catch (err) {
      if (err instanceof ApiError && err.code === "fresh_login_required") {
        signIn(exportReturnPath(name));
        return;
      }
      if (err instanceof ApiError && err.reauth) return;
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  async function copy(): Promise<void> {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.root_key);
      copied = true;
    } catch {
      error = "Couldn't copy. Select the key and copy it by hand.";
    }
  }

  // Built in the browser from the config this page loaded; nothing goes to a server.
  function downloadConfig(): void {
    const { filename, text } = configFile(name, $state.snapshot(config) as Config);
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function hide(): void {
    result = null;
    copied = false;
  }
</script>

<section class="card space-y-4 p-4">
  <h2 class="section-title">Export the root key</h2>
  {#if result}
    <div class="notice notice-warn">
      This is the only time the console shows this key. Store it somewhere safe now; leaving this
      page clears it.
    </div>
    <dl class="space-y-3 text-sm">
      <div>
        <dt class="label">Root id</dt>
        <dd><code data-testid="export-root-id">{result.root_id}</code></dd>
      </div>
      <div>
        <dt class="label">Root key (base64)</dt>
        <dd>
          <code
            class="block rounded border border-line bg-sunken p-2 text-xs break-all select-all"
            data-testid="export-root-key">{result.root_key}</code
          >
        </dd>
      </div>
    </dl>
    <div class="flex flex-wrap gap-2">
      <button type="button" class="btn btn-primary" onclick={copy}>
        {copied ? "Copied" : "Copy key"}
      </button>
      <button type="button" class="btn" onclick={downloadConfig}>Download config</button>
      <button type="button" class="btn" onclick={hide}>Done, hide it</button>
    </div>
    <p class="hint">
      Keep the config with the key: decrypting offline needs its key ids as well.
    </p>
  {:else}
    <div class="space-y-2 text-sm">
      <p>
        The root key is the secret every key in <strong>{name}</strong> derives from. With it, the
        root id and this tenant's config, anyone can decrypt everything this tenant has encrypted,
        on their own machine, without edgekms. Export it to keep an offline backup or to move the
        tenant to a self-hosted Worker.
      </p>
      <p>
        Decrypting offline needs the config too, since each key's material comes from the root key
        and the key's id, and the ids are in the config. Keep a copy with the key.
      </p>
      <div>
        <button type="button" class="btn" onclick={downloadConfig}>Download config</button>
        <span class="ml-2 text-xs text-muted">
          {name}-config.json, the saved config. It holds no secrets.
        </span>
      </div>
      <p class="text-muted">
        Every export is recorded in the audit log. It needs a sign-in under five minutes old: if
        yours is older, you'll sign in again and come back here to confirm.
      </p>
      <p class="text-muted" data-testid="export-help">
        Storing the key safely, and decrypting offline with the CLI:
        <Help section="export" />
      </p>
    </div>
    <form class="space-y-3" onsubmit={doExport}>
      <div>
        <label class="label" for="export-confirm">Type the tenant name to confirm</label>
        <input
          id="export-confirm"
          class="input sm:max-w-sm"
          bind:value={typed}
          placeholder={name}
          autocomplete="off"
          spellcheck="false"
        />
      </div>
      <button type="submit" class="btn btn-danger" disabled={!ready || busy}>
        {busy ? "Exporting..." : "Export root key"}
      </button>
    </form>
  {/if}
  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}
</section>
