<script lang="ts">
  import { addKey, raiseMinDecryption, rotateKey, type Config } from "../lib/config";

  let {
    config,
    update,
    readonly,
  }: { config: Config; update: (c: Config) => void; readonly: boolean } = $props();

  let newName = $state("");
  let error = $state<string | null>(null);
  // The key whose "raise minimum" form is open, and the version typed in it.
  let raising = $state<string | null>(null);
  let raiseTo = $state<number>(1);

  const keys = $derived(Object.entries(config.keys));

  function attempt(f: () => Config): boolean {
    error = null;
    try {
      update(f());
      return true;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      return false;
    }
  }

  function rotate(name: string): void {
    attempt(() => rotateKey(config, name));
  }

  function openRaise(name: string): void {
    const key = config.keys[name];
    if (!key) return;
    raising = name;
    raiseTo = key.latest_version;
    error = null;
  }

  function raise(e: SubmitEvent): void {
    e.preventDefault();
    const name = raising;
    if (name === null) return;
    const version = Number(raiseTo);
    const ok = confirm(
      `Raise the minimum decryption version of ${name} to ${version}? Ciphertext under versions ` +
        `below ${version} stops decrypting once you save.`,
    );
    if (ok && attempt(() => raiseMinDecryption(config, name, version))) raising = null;
  }

  function add(e: SubmitEvent): void {
    e.preventDefault();
    error = null;
    try {
      update(addKey(config, newName.trim()));
      newName = "";
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  }
</script>

<section class="card">
  <div class="border-b border-line px-4 py-3">
    <h2 class="section-title">Keys</h2>
    <p class="hint">
      A key's material comes from the tenant root and its id. The editor never removes a key:
      removing one leaves everything encrypted under it undecryptable until someone re-adds it with
      the same id. The Raw JSON tab can still remove one.
    </p>
  </div>
  {#if keys.length === 0}
    <p class="px-4 py-6 text-sm text-muted">No keys yet.</p>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="text-left text-xs text-muted">
          <tr>
            <th class="px-4 py-2 font-medium">Name</th>
            <th class="px-4 py-2 font-medium">Id</th>
            <th class="px-4 py-2 text-right font-medium">Latest version</th>
            <th class="px-4 py-2 text-right font-medium">Min decryption version</th>
            {#if !readonly}
              <th class="px-4 py-2 font-medium"><span class="sr-only">Actions</span></th>
            {/if}
          </tr>
        </thead>
        <tbody class="divide-y divide-line">
          {#each keys as [name, key] (name)}
            <tr data-testid="key-row" data-key={name}>
              <td class="px-4 py-2 font-medium">{name}</td>
              <td class="px-4 py-2"><code class="text-xs">{key.id}</code></td>
              <td class="px-4 py-2 text-right tabular-nums">{key.latest_version}</td>
              <td class="px-4 py-2 text-right tabular-nums">{key.min_decryption_version}</td>
              {#if !readonly}
                <td class="px-4 py-2">
                  <div class="flex justify-end gap-1">
                    <button
                      type="button"
                      class="btn btn-quiet"
                      aria-label={`Rotate ${name}`}
                      onclick={() => rotate(name)}>Rotate</button
                    >
                    {#if key.min_decryption_version < key.latest_version}
                      <button
                        type="button"
                        class="btn btn-quiet whitespace-nowrap"
                        aria-label={`Raise minimum decryption version of ${name}`}
                        onclick={() => openRaise(name)}>Raise minimum</button
                      >
                    {/if}
                  </div>
                </td>
              {/if}
            </tr>
            {#if raising === name}
              <tr>
                <td colspan="5" class="px-4 py-3">
                  <form
                    class="notice notice-warn space-y-2"
                    onsubmit={raise}
                    data-testid="raise-form"
                  >
                    <p>
                      Raising the minimum decryption version retires older versions: ciphertext
                      under any version below it stops decrypting once you save. Rewrap that
                      ciphertext to the latest version first.
                    </p>
                    <div class="flex flex-wrap items-end gap-2">
                      <div>
                        <label class="label" for="raise-to">New minimum decryption version</label>
                        <input
                          id="raise-to"
                          class="input w-32"
                          type="number"
                          min={key.min_decryption_version + 1}
                          max={key.latest_version}
                          bind:value={raiseTo}
                          required
                        />
                      </div>
                      <button type="submit" class="btn btn-danger">Raise minimum</button>
                      <button type="button" class="btn" onclick={() => (raising = null)}
                        >Cancel</button
                      >
                    </div>
                  </form>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if !readonly}
    <form class="flex flex-col gap-2 border-t border-line px-4 py-3 sm:flex-row" onsubmit={add}>
      <label for="key-name" class="sr-only">New key name</label>
      <input
        id="key-name"
        class="input sm:max-w-xs"
        bind:value={newName}
        placeholder="key name, for example signing"
        autocomplete="off"
        spellcheck="false"
        required
      />
      <button type="submit" class="btn">Add key</button>
    </form>
    {#if error}
      <p class="px-4 pb-3 text-sm text-danger" role="alert">{error}</p>
    {/if}
  {/if}
</section>
