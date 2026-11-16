<script lang="ts">
  import { ApiError, request, tenantPath, type Created, type Me } from "../lib/api";
  import { navigate } from "../lib/router";

  let { me, reload }: { me: Me; reload: () => Promise<void> } = $props();

  let busy = $state<string | null>(null);
  let error = $state<string | null>(null);
  let newName = $state("");

  const example = $derived(
    me.login.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "you",
  );

  function fail(e: unknown): void {
    if (e instanceof ApiError && e.reauth) return;
    error = e instanceof Error ? e.message : String(e);
  }

  async function answer(name: string, verb: "accept" | "decline"): Promise<void> {
    if (verb === "decline" && !confirm(`Decline the invite to ${name}?`)) return;
    busy = `${verb}:${name}`;
    error = null;
    try {
      await request("POST", `${tenantPath(name)}/${verb}`);
      await reload();
    } catch (e) {
      fail(e);
    } finally {
      busy = null;
    }
  }

  async function create(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const name = newName.trim();
    if (name === "") return;
    busy = "create";
    error = null;
    try {
      const created = await request<Created>("POST", "/tenants", { body: { name } });
      newName = "";
      await reload();
      navigate(`/t/${encodeURIComponent(created.name)}`);
    } catch (err) {
      fail(err);
    } finally {
      busy = null;
    }
  }
</script>

<div class="space-y-6">
  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}

  {#if me.invites.length > 0}
    <section class="card" aria-labelledby="invites-title">
      <h2 id="invites-title" class="section-title border-b border-line px-4 py-3">
        Pending invites
      </h2>
      <ul class="divide-y divide-line">
        {#each me.invites as invite (invite.name)}
          <li class="flex flex-wrap items-center gap-3 px-4 py-3" data-testid="invite">
            <div class="min-w-0 flex-1">
              <span class="font-medium">{invite.name}</span>
              <span class="ml-2 text-sm text-muted">as {invite.role}</span>
            </div>
            <div class="flex gap-2">
              <button
                type="button"
                class="btn btn-primary"
                disabled={busy !== null}
                onclick={() => answer(invite.name, "accept")}>Accept</button
              >
              <button
                type="button"
                class="btn"
                disabled={busy !== null}
                onclick={() => answer(invite.name, "decline")}>Decline</button
              >
            </div>
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <section class="card" aria-labelledby="tenants-title">
    <h2 id="tenants-title" class="section-title border-b border-line px-4 py-3">Your tenants</h2>
    {#if me.tenants.length === 0}
      <p class="px-4 py-6 text-sm text-muted">You aren't a member of any tenant yet.</p>
    {:else}
      <ul class="divide-y divide-line">
        {#each me.tenants as t (t.name)}
          <li data-testid="tenant">
            <a
              href={`/t/${encodeURIComponent(t.name)}`}
              class="flex flex-wrap items-center gap-3 px-4 py-3 hover:bg-sunken"
            >
              <span class="min-w-0 flex-1 truncate font-medium">{t.name}</span>
              <span class="badge">{t.role}</span>
              {#if t.status === "active"}
                <span class="badge badge-ok">active</span>
              {:else}
                <span class="badge badge-warn">suspended</span>
              {/if}
            </a>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="card p-4" aria-labelledby="new-title">
    <h2 id="new-title" class="section-title">New tenant</h2>
    <form class="mt-3 flex flex-col gap-3 sm:flex-row sm:items-start" onsubmit={create}>
      <div class="flex-1">
        <label for="new-name" class="sr-only">Tenant name</label>
        <input
          id="new-name"
          class="input"
          bind:value={newName}
          placeholder={`${example}-prod`}
          autocomplete="off"
          spellcheck="false"
          required
        />
        {#if !me.operator}
          <p class="hint">
            The name must start with your GitHub login and a dash, for example
            <code>{example}-prod</code>. If yours doesn't fit, the error tells you the prefix to use.
            Importing an existing root key at creation is CLI-only.
          </p>
        {/if}
      </div>
      <button type="submit" class="btn btn-primary" disabled={busy !== null}>Create</button>
    </form>
  </section>
</div>
