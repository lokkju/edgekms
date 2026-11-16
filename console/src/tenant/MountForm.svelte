<script lang="ts">
  import { untrack } from "svelte";
  import { GITHUB_ACTIONS_MOUNT, type Mount } from "../lib/config";

  type Kind = "ssh" | "actions" | "oidc";

  let {
    name: initialName = "",
    mount,
    save,
    cancel,
  }: {
    name?: string;
    mount?: Mount;
    save: (name: string, mount: Mount) => string | null;
    cancel: () => void;
  } = $props();

  const uid = $props.id();
  const actions = GITHUB_ACTIONS_MOUNT as Extract<Mount, { type: "jwt" }>;

  function kindOf(m: Mount | undefined): Kind {
    if (!m) return "actions";
    if (m.type === "ssh") return "ssh";
    if (m.type === "jwt" && m.issuer === actions.issuer && m.jwks_url === actions.jwks_url) {
      return "actions";
    }
    return "oidc";
  }

  // The form edits a snapshot of the props it opened with; it doesn't follow later prop changes.
  const start = untrack(() => $state.snapshot({ initialName, mount }));
  const jwtStart = start.mount?.type === "jwt" ? start.mount : undefined;

  let name = $state(start.initialName);
  let kind = $state<Kind>(kindOf(start.mount));
  let issuer = $state(jwtStart?.issuer ?? "https://");
  let source = $state<"url" | "inline">(jwtStart?.jwks !== undefined ? "inline" : "url");
  let jwksUrl = $state(jwtStart?.jwks_url ?? "https://");
  let jwksText = $state(jwtStart?.jwks !== undefined ? JSON.stringify(jwtStart.jwks, null, 2) : "");
  let error = $state<string | null>(null);

  const editing = start.mount !== undefined;

  function build(): Mount {
    if (kind === "ssh") return { type: "ssh" };
    if (kind === "actions") return { ...actions };
    if (source === "url") return { type: "jwt", issuer: issuer.trim(), jwks_url: jwksUrl.trim() };
    let jwks: unknown;
    try {
      jwks = JSON.parse(jwksText);
    } catch {
      throw new Error("the inline JWKS isn't valid JSON");
    }
    return { type: "jwt", issuer: issuer.trim(), jwks };
  }

  function submit(e: SubmitEvent): void {
    e.preventDefault();
    error = null;
    try {
      error = save(name.trim(), build());
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  }
</script>

<form class="space-y-3 rounded-md border border-line bg-sunken p-3" onsubmit={submit}>
  <div class="grid gap-3 sm:grid-cols-2">
    <div>
      <label class="label" for={`${uid}-name`}>Mount name</label>
      <input
        id={`${uid}-name`}
        class="input"
        bind:value={name}
        required
        autocomplete="off"
        spellcheck="false"
      />
    </div>
    <div>
      <label class="label" for={`${uid}-kind`}>Type</label>
      <select id={`${uid}-kind`} class="input" bind:value={kind} disabled={editing && kind === "ssh"}>
        {#if !editing || kind === "ssh"}
          <option value="ssh">SSH keys</option>
        {/if}
        <option value="actions">GitHub Actions (OIDC)</option>
        <option value="oidc">Other OIDC</option>
      </select>
    </div>
  </div>

  {#if kind === "actions"}
    <p class="hint">
      Issuer <code>{actions.issuer}</code>, keys from <code>{actions.jwks_url}</code>.
    </p>
  {:else if kind === "oidc"}
    <div>
      <label class="label" for={`${uid}-issuer`}>Issuer</label>
      <input id={`${uid}-issuer`} class="input" bind:value={issuer} required spellcheck="false" />
    </div>
    <fieldset class="space-y-2">
      <legend class="label">Signing keys</legend>
      <div class="flex flex-wrap gap-4 text-sm">
        <label class="inline-flex items-center gap-1.5">
          <input type="radio" value="url" bind:group={source} /> From a JWKS URL
        </label>
        <label class="inline-flex items-center gap-1.5">
          <input type="radio" value="inline" bind:group={source} /> Inline JWKS
        </label>
      </div>
      {#if source === "url"}
        <label for={`${uid}-jwks-url`} class="sr-only">JWKS URL</label>
        <input id={`${uid}-jwks-url`} class="input" bind:value={jwksUrl} required spellcheck="false" />
      {:else}
        <label for={`${uid}-jwks`} class="sr-only">JWKS JSON</label>
        <textarea
          id={`${uid}-jwks`}
          class="input h-32 font-mono text-xs"
          bind:value={jwksText}
          placeholder={'{"keys": [...]}'}
          spellcheck="false"
        ></textarea>
      {/if}
    </fieldset>
  {/if}

  {#if error}
    <p class="text-sm text-danger" role="alert">{error}</p>
  {/if}
  <div class="flex gap-2">
    <button type="submit" class="btn btn-primary">{editing ? "Apply" : "Add mount"}</button>
    <button type="button" class="btn" onclick={cancel}>Cancel</button>
  </div>
</form>
