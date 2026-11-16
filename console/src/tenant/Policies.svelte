<script lang="ts">
  import {
    ADMIN_CAPABILITIES,
    CAPABILITIES,
    addPolicy,
    capabilityGrid,
    removePolicy,
    setAdmin,
    setCapability,
    type Config,
  } from "../lib/config";
  import Help from "../lib/Help.svelte";

  let {
    config,
    update,
    readonly,
  }: { config: Config; update: (c: Config) => void; readonly: boolean } = $props();

  let newName = $state("");
  let error = $state<string | null>(null);

  const policies = $derived(Object.keys(config.policies));
  const keyNames = $derived(Object.keys(config.keys));

  function attempt(f: () => Config): void {
    error = null;
    try {
      update(f());
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  }

  function add(e: SubmitEvent): void {
    e.preventDefault();
    attempt(() => addPolicy(config, newName.trim()));
    if (error === null) newName = "";
  }
</script>

<div class="space-y-4">
  <p class="text-sm text-muted" data-testid="policies-help">
    A policy grants capabilities on keys: <strong>encrypt</strong>, <strong>decrypt</strong>,
    <strong>rewrap</strong> (re-encrypt under the latest version without returning the plaintext)
    and <strong>read</strong> (the key's versions, never its material).
    <strong>token-create</strong> and <strong>token-revoke</strong> let a token mint and revoke
    others. A token gets everything its role's policies grant, and nothing else.
    <Help section="policies" />
  </p>

  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}

  {#each policies as policy (policy)}
    {@const grid = capabilityGrid(config, policy)}
    {@const admin = new Set(config.policies[policy]?.admin ?? [])}
    <section class="card" data-testid="policy" data-policy={policy}>
      <div class="flex items-center gap-2 border-b border-line px-4 py-3">
        <h2 class="section-title min-w-0 flex-1 truncate">{policy}</h2>
        {#if !readonly}
          <button
            type="button"
            class="btn btn-quiet text-danger"
            onclick={() => {
              if (confirm(`Remove policy ${policy}?`)) attempt(() => removePolicy(config, policy));
            }}>Remove</button
          >
        {/if}
      </div>
      {#if keyNames.length === 0}
        <p class="px-4 py-3 text-sm text-muted">The config has no keys to grant.</p>
      {:else}
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-xs text-muted">
              <tr>
                <th class="px-4 py-2 font-medium">Key</th>
                {#each CAPABILITIES as cap (cap)}
                  <th class="px-3 py-2 text-center font-medium">{cap}</th>
                {/each}
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              {#each keyNames as key (key)}
                <tr>
                  <td class="px-4 py-2 font-medium">{key}</td>
                  {#each CAPABILITIES as cap (cap)}
                    <td class="px-3 py-2 text-center">
                      <input
                        type="checkbox"
                        class="h-4 w-4 accent-accent"
                        aria-label={`${policy}: ${cap} on ${key}`}
                        checked={grid[key]?.has(cap) ?? false}
                        disabled={readonly}
                        onchange={(e) =>
                          attempt(() =>
                            setCapability(config, policy, key, cap, e.currentTarget.checked),
                          )}
                      />
                    </td>
                  {/each}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <div class="flex flex-wrap items-center gap-4 border-t border-line px-4 py-3 text-sm">
        <span class="text-muted">Admin:</span>
        {#each ADMIN_CAPABILITIES as cap (cap)}
          <label class="inline-flex items-center gap-1.5">
            <input
              type="checkbox"
              class="h-4 w-4 accent-accent"
              checked={admin.has(cap)}
              disabled={readonly}
              onchange={(e) => attempt(() => setAdmin(config, policy, cap, e.currentTarget.checked))}
            />
            {cap}
          </label>
        {/each}
      </div>
    </section>
  {/each}

  {#if !readonly}
    <form class="card flex flex-col gap-2 p-4 sm:flex-row" onsubmit={add}>
      <label for="policy-name" class="sr-only">New policy name</label>
      <input
        id="policy-name"
        class="input sm:max-w-xs"
        bind:value={newName}
        placeholder="policy name"
        autocomplete="off"
        spellcheck="false"
        required
      />
      <button type="submit" class="btn">Add policy</button>
    </form>
  {/if}
</div>
