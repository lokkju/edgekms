<script lang="ts">
  import { onMount } from "svelte";
  import {
    ApiError,
    request,
    signIn,
    type Me,
    type SshKey,
    type SshKeyChallenge,
    type SshKeyList,
  } from "../lib/api";
  import {
    addErrorMessage,
    addedBy,
    checkLabel,
    countdown,
    defaultLabel,
    fingerprint,
    keyId,
    keyName,
    lineage,
    needsTouch,
    parsePublicKey,
    registerAccount,
    saveDraft,
    signingCommand,
    takeDraft,
    type RegisterAccount,
  } from "../lib/sshkeys";

  let { me }: { me: Me } = $props();

  let list = $state<SshKeyList | null>(null);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let busy = $state(false);
  let copied = $state<string | null>(null);

  // The add form. The pasted key and label are the only things that ever go to sessionStorage,
  // and only for the sign-in detour.
  let pasted = $state("");
  let label = $state("");
  let labelEdited = $state(false);
  let browserFingerprint = $state<string | null>(null);
  let challenge = $state<{
    text: string;
    command: string;
    account: RegisterAccount;
    expiresAt: number;
  } | null>(null);
  let signature = $state("");
  let addError = $state<string | null>(null);
  let now = $state(Date.now());

  // Removal: the key, and for each key it added whether to remove that one too.
  let removing = $state<{ key: SshKey; children: SshKey[]; checked: Record<string, boolean> } | null>(
    null,
  );

  const parsed = $derived(pasted.trim() === "" ? null : parsePublicKey(pasted));
  const labelCheck = $derived(checkLabel(label));
  const keys = $derived(list?.keys ?? []);
  const anyWithoutTouch = $derived(keys.some((k) => !needsTouch(k.key_type)));
  const left = $derived(challenge ? challenge.expiresAt - now : 0);
  const expired = $derived(challenge !== null && left <= 0);

  // The label follows the pasted key's comment until someone types their own.
  $effect(() => {
    if (labelEdited) return;
    label = parsed?.ok ? defaultLabel(parsed.key.comment) : "";
  });

  $effect(() => {
    const p = parsed;
    browserFingerprint = null;
    if (!p?.ok) return;
    let stale = false;
    void fingerprint(p.key.blob).then((fp) => {
      if (!stale) browserFingerprint = fp;
    });
    return () => {
      stale = true;
    };
  });

  $effect(() => {
    if (challenge === null) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  function fail(e: unknown): void {
    if (e instanceof ApiError && e.reauth) return;
    error = e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    try {
      list = await request<SshKeyList>("GET", "/me/ssh-keys");
    } catch (e) {
      fail(e);
    }
  }

  onMount(() => {
    let draft = null;
    try {
      draft = takeDraft(sessionStorage);
    } catch {
      // No sessionStorage at all.
    }
    if (draft) {
      pasted = draft.public_key;
      label = draft.label;
      labelEdited = true;
      notice = "You're signed in again. Your key and label are back: get a signing command to go on.";
    }
    void load();
  });

  /** Off to sign in for a fresh session, keeping the public key and label for the way back. */
  function detour(): void {
    try {
      saveDraft(sessionStorage, { public_key: pasted, label });
    } catch {
      // No sessionStorage: the form comes back empty.
    }
    signIn("/account");
  }

  function localProblem(): string | null {
    if (parsed === null) return "Paste a public key first.";
    if (!parsed.ok) return addErrorMessage(parsed.error);
    if (!labelCheck.ok) return addErrorMessage("label_invalid");
    return null;
  }

  async function getCommand(): Promise<void> {
    addError = localProblem();
    if (addError !== null) return;
    busy = true;
    error = null;
    notice = null;
    try {
      const c = await request<SshKeyChallenge>("POST", "/me/ssh-keys/challenge", { body: {} });
      // The challenge names the account the key goes to, in the text that's signed. Never offer
      // one naming anyone but the signed-in user: the signature would register the key to them.
      const account = registerAccount(c.challenge);
      if (account === null || account.githubId !== me.github_id) {
        challenge = null;
        addError =
          account === null
            ? "The control plane's challenge doesn't say which account it's for. Don't sign it; reload the page and try again."
            : `The control plane's challenge would register the key to GitHub account ${account.login} (${account.githubId}), not to you (${me.login}, ${me.github_id}). Don't sign it; reload the page and try again.`;
        return;
      }
      challenge = {
        text: c.challenge,
        command: signingCommand(c.challenge),
        account,
        expiresAt: Date.now() + c.expires_in * 1000,
      };
      signature = "";
    } catch (e) {
      if (e instanceof ApiError && e.code === "fresh_login_required") {
        detour();
        return;
      }
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function addKey(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    addError = localProblem();
    if (addError !== null || challenge === null) return;
    if (!signature.includes("-----BEGIN SSH SIGNATURE-----")) {
      addError = "Paste the whole signature, from -----BEGIN SSH SIGNATURE----- to its END line.";
      return;
    }
    busy = true;
    error = null;
    notice = null;
    try {
      const to = challenge.account;
      const added = await request<SshKey>("POST", "/me/ssh-keys", {
        body: {
          public_key: pasted.trim(),
          label: labelCheck.ok ? labelCheck.label : label,
          challenge: challenge.text,
          signature: signature.trim() + "\n",
        },
      });
      pasted = "";
      label = "";
      labelEdited = false;
      challenge = null;
      signature = "";
      notice = `Added ${keyName(added)} to GitHub account ${to.login} (${to.githubId}). It can log in with edgekms account login --ssh.`;
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === "fresh_login_required") {
        detour();
        return;
      }
      if (err instanceof ApiError && err.reauth) return;
      const sentence = err instanceof ApiError ? addErrorMessage(err.code) : null;
      addError = sentence ?? (err instanceof Error ? err.message : String(err));
      if (err instanceof ApiError && err.code === "ssh_key_proof_failed") {
        challenge = null;
        signature = "";
      }
    } finally {
      busy = false;
    }
  }

  async function copy(what: string, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      copied = what;
    } catch {
      error = "Couldn't copy. Select the text and copy it by hand.";
    }
  }

  function startRemove(key: SshKey): void {
    const children = addedBy(keys, key);
    removing = { key, children, checked: Object.fromEntries(children.map((c) => [c.id, true])) };
  }

  async function remove(): Promise<void> {
    const r = removing;
    if (!r) return;
    const targets = [r.key, ...r.children.filter((c) => r.checked[c.id])];
    busy = true;
    error = null;
    notice = null;
    try {
      for (const k of targets) await request("DELETE", `/me/ssh-keys/${encodeURIComponent(k.id)}`);
      removing = null;
      notice =
        targets.length === 1
          ? `Removed ${keyName(r.key)}.`
          : `Removed ${targets.map((k) => keyName(k)).join(", ")}.`;
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      await load();
    }
  }

  async function removeUnverified(fp: string): Promise<void> {
    const id = keyId(fp);
    if (id === null) return;
    if (!confirm(`Delete the record for ${fp}? It can't log in as it is.`)) return;
    busy = true;
    error = null;
    notice = null;
    try {
      await request("DELETE", `/me/ssh-keys/${encodeURIComponent(id)}`);
      notice = `Deleted the record for ${fp}.`;
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      await load();
    }
  }

  const date = (ms: number) => new Date(ms).toISOString().slice(0, 10);
</script>

<div class="space-y-4">
  <h1 class="text-xl font-semibold">Account</h1>
  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}
  {#if notice}
    <div class="notice notice-ok" role="status">{notice}</div>
  {/if}

  <section class="card">
    <div class="border-b border-line px-4 py-3">
      <h2 class="section-title">SSH keys</h2>
      <p class="hint">
        Keys that can log in to the control plane as you with
        <code>edgekms account login --ssh</code>, for when GitHub sign-in isn't available. A key
        logs in to your account only; it can't create one.
      </p>
    </div>

    {#if list === null}
      <p class="px-4 py-3 text-sm text-muted">Loading...</p>
    {:else}
      {#if keys.length === 0}
        <p class="px-4 py-3 text-sm text-muted">No SSH keys yet.</p>
      {:else}
        <div class="relative overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-xs text-muted">
              <tr>
                <th class="px-4 py-2 font-medium">Label</th>
                <th class="px-4 py-2 font-medium">Type</th>
                <th class="px-4 py-2 font-medium">Fingerprint</th>
                <th class="px-4 py-2 font-medium">Added</th>
                <th class="px-4 py-2 font-medium">Last used</th>
                <th class="px-4 py-2 font-medium"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              {#each keys as key (key.id)}
                <tr data-testid="ssh-key" data-fingerprint={key.fingerprint}>
                  <td class="min-w-28 px-4 py-2 font-medium">
                    {#if key.label !== ""}{key.label}{:else}<span class="text-muted">no label</span
                      >{/if}
                  </td>
                  <td class="px-4 py-2">
                    <code class="text-xs">{key.key_type}</code>
                    {#if !needsTouch(key.key_type)}
                      <span class="badge badge-warn ml-1 whitespace-nowrap" data-testid="no-touch"
                        >no touch required</span
                      >
                    {/if}
                  </td>
                  <td class="px-4 py-2">
                    <div class="flex items-center gap-1">
                      <code class="text-xs break-all" data-testid="fingerprint">{key.fingerprint}</code>
                      <button
                        type="button"
                        class="btn btn-quiet px-2 py-0.5 text-xs"
                        aria-label={`Copy fingerprint of ${keyName(key)}`}
                        onclick={() => copy(key.id, key.fingerprint)}
                        >{copied === key.id ? "Copied" : "Copy"}</button
                      >
                    </div>
                  </td>
                  <td class="px-4 py-2">
                    <div class="whitespace-nowrap tabular-nums">{date(key.added_ms)}</div>
                    <div class="text-xs text-muted" data-testid="lineage">{lineage(key, keys)}</div>
                  </td>
                  <td class="px-4 py-2 whitespace-nowrap tabular-nums">
                    {#if key.last_used_ms === null}<span class="text-muted">never</span
                      >{:else}{date(key.last_used_ms)}{/if}
                  </td>
                  <td class="px-4 py-2 text-right">
                    <button
                      type="button"
                      class="btn btn-quiet text-danger"
                      disabled={busy}
                      aria-label={`Delete ${keyName(key)}`}
                      onclick={() => startRemove(key)}>Delete</button
                    >
                  </td>
                </tr>
                {#if removing?.key.id === key.id}
                  {@const r = removing}
                  <tr>
                    <td colspan="6" class="px-4 py-3">
                      <div class="notice notice-warn space-y-2" data-testid="remove-confirm">
                        <p>
                          Remove <strong>{keyName(key)}</strong> (<code class="text-xs break-all"
                            >{key.fingerprint}</code
                          >)? It can't log in once it's gone, and any CLI session it started ends
                          on its next request.
                        </p>
                        {#if r.children.length > 0}
                          <fieldset class="space-y-1">
                            <legend class="font-medium">Also remove keys this key added</legend>
                            {#each r.children as child (child.id)}
                              <label class="flex items-center gap-2">
                                <input type="checkbox" bind:checked={r.checked[child.id]} />
                                <span>{keyName(child)}</span>
                                <code class="text-xs break-all text-muted">{child.fingerprint}</code>
                              </label>
                            {/each}
                          </fieldset>
                        {/if}
                        <div class="flex gap-2">
                          <button type="button" class="btn btn-danger" disabled={busy} onclick={remove}
                            >Remove</button
                          >
                          <button type="button" class="btn btn-quiet" onclick={() => (removing = null)}
                            >Cancel</button
                          >
                        </div>
                      </div>
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
        {#if anyWithoutTouch}
          <p class="px-4 pb-3 text-xs text-muted" data-testid="touch-advice">
            A key marked "no touch required" signs whenever anything that can reach your ssh-agent
            asks. A security key (<code>sk-ssh-ed25519</code>), or adding the key with
            <code>ssh-add -c</code> so the agent asks you first, closes that gap.
          </p>
        {/if}
      {/if}
      {#if list.unverified.length > 0}
        <div class="notice notice-warn mx-4 mb-3 space-y-2" data-testid="unverified-keys">
          <p>This key's record failed its integrity check and can't log in.</p>
          <ul class="space-y-1">
            {#each list.unverified as fp (fp)}
              <li class="flex flex-wrap items-center gap-2">
                <code class="text-xs break-all">{fp}</code>
                <button
                  type="button"
                  class="btn btn-quiet text-danger"
                  disabled={busy}
                  aria-label={`Delete ${fp}`}
                  onclick={() => removeUnverified(fp)}>Delete</button
                >
              </li>
            {/each}
          </ul>
        </div>
      {/if}
    {/if}

    <form class="space-y-4 border-t border-line px-4 py-4" onsubmit={addKey} data-testid="add-key">
      <div>
        <h3 class="font-medium">Add a key</h3>
        <p class="hint">
          Adding a key needs a sign-in under five minutes old: if yours is older, you'll sign in
          again and come back here with the key and label still filled in. The CLI's
          <code>edgekms account ssh-keys add</code> does all three steps at once.
        </p>
      </div>

      <ol class="space-y-4">
        <li class="space-y-2">
          <p class="text-sm font-medium">1. Paste the public key</p>
          <div>
            <label class="label" for="ssh-public-key">Public key</label>
            <textarea
              id="ssh-public-key"
              class="input font-mono text-xs"
              rows="3"
              bind:value={pasted}
              placeholder="ssh-ed25519 AAAAC3Nza... you@laptop"
              autocomplete="off"
              spellcheck="false"
            ></textarea>
            <p class="hint">
              The contents of the key's <code>.pub</code> file, such as
              <code>~/.ssh/id_ed25519.pub</code>, or a line of <code>ssh-add -L</code>.
            </p>
          </div>
          {#if parsed?.ok}
            <p class="text-sm" data-testid="browser-fingerprint">
              <code class="text-xs">{parsed.key.keyType}</code>
              <code class="text-xs break-all">{browserFingerprint ?? "..."}</code>
              <span class="block text-xs text-muted"
                >Check it against what <code>ssh-keygen -lf</code> prints for the key.</span
              >
            </p>
          {:else if parsed && !parsed.ok}
            <p class="text-sm text-danger" data-testid="key-problem">{addErrorMessage(parsed.error)}</p>
          {/if}
          <div>
            <label class="label" for="ssh-label">Label (optional)</label>
            <input
              id="ssh-label"
              class="input sm:max-w-sm"
              bind:value={label}
              oninput={() => (labelEdited = true)}
              autocomplete="off"
              spellcheck="false"
            />
            {#if !labelCheck.ok}
              <p class="hint text-danger" data-testid="label-problem">{labelCheck.reason}</p>
            {/if}
          </div>
        </li>

        <li class="space-y-2">
          <p class="text-sm font-medium">2. Sign a challenge with it</p>
          <button
            type="button"
            class="btn"
            disabled={busy || !parsed?.ok || !labelCheck.ok}
            onclick={getCommand}>Get a signing command</button
          >
          {#if challenge}
            <div class="space-y-2">
              <p class="text-sm" data-testid="register-account">
                This registers the key to your GitHub account <strong>{challenge.account.login}</strong>
                ({challenge.account.githubId}).
              </p>
              <code
                class="block rounded border border-line bg-sunken p-2 text-xs break-all select-all"
                data-testid="signing-command">{challenge.command}</code
              >
              <div class="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  class="btn"
                  onclick={() => challenge && copy("command", challenge.command)}
                  >{copied === "command" ? "Copied" : "Copy command"}</button
                >
                {#if expired}
                  <span class="text-sm text-danger" data-testid="countdown"
                    >This command has expired; get a new one.</span
                  >
                {:else}
                  <span class="text-sm text-muted tabular-nums" data-testid="countdown"
                    >Expires in {countdown(left)}</span
                  >
                {/if}
              </div>
              <p class="hint">
                Run it in a terminal, with <code>-f</code> naming the key you pasted (ssh-keygen
                uses the agent's private key for it). Keep <code>printf '%s'</code>: a trailing
                newline, as <code>echo</code> or <code>&lt;&lt;&lt;</code> add, changes what is
                signed and the signature won't match.
              </p>
            </div>
          {/if}
        </li>

        <li class="space-y-2">
          <p class="text-sm font-medium">3. Paste the signature</p>
          <div>
            <label class="label" for="ssh-signature">Signature</label>
            <textarea
              id="ssh-signature"
              class="input font-mono text-xs"
              rows="6"
              bind:value={signature}
              placeholder={"-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----"}
              autocomplete="off"
              spellcheck="false"
              disabled={challenge === null}
            ></textarea>
          </div>
          <button
            type="submit"
            class="btn btn-primary"
            disabled={busy || challenge === null || expired || signature.trim() === ""}
            >Add key</button
          >
        </li>
      </ol>
      {#if addError}
        <div class="notice notice-error" role="alert" data-testid="add-error">{addError}</div>
      {/if}
    </form>
  </section>
</div>
