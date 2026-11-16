<script lang="ts">
  import type { Config } from "../lib/config";

  let {
    config,
    update,
    readonly,
    setInvalid,
  }: {
    config: Config;
    update: (c: Config) => void;
    readonly: boolean;
    setInvalid: (invalid: boolean) => void;
  } = $props();

  const format = (c: Config) => JSON.stringify(c, null, 2);

  let text = $state("");
  let error = $state<string | null>(null);
  // The JSON this editor last handed up. A config change that isn't that (a reload, a discard)
  // replaces the text; one that is leaves the user's formatting alone.
  let emitted = "";

  $effect(() => {
    const incoming = JSON.stringify(config);
    if (incoming !== emitted) {
      text = format(config);
      emitted = incoming;
      error = null;
      setInvalid(false);
    }
  });

  function onInput(): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      error = e instanceof Error ? e.message : "not valid JSON";
      setInvalid(true);
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      error = "the config must be a JSON object";
      setInvalid(true);
      return;
    }
    error = null;
    setInvalid(false);
    emitted = JSON.stringify(parsed);
    update(parsed as Config);
  }
</script>

<section class="card p-4">
  <h2 class="section-title">Raw JSON</h2>
  <p class="hint">
    The whole config. The server checks it on save and names the first problem it finds.
  </p>
  <label for="raw-json" class="sr-only">Config JSON</label>
  <textarea
    id="raw-json"
    class="input mt-3 h-[60vh] font-mono text-xs"
    spellcheck="false"
    autocomplete="off"
    readonly={readonly}
    bind:value={text}
    oninput={onInput}
  ></textarea>
  {#if error}
    <p class="mt-2 text-sm text-danger" role="alert" data-testid="raw-error">Not valid JSON: {error}</p>
  {/if}
</section>
