<script lang="ts">
  import { untrack } from "svelte";
  import { ApiError, request, tenantPath, type Me, type TenantDetail } from "../lib/api";
  import type { Config } from "../lib/config";
  import { tenantOrigin } from "../lib/actions";
  import { saveConfig } from "../tenant/save";
  import Keys from "../tenant/Keys.svelte";
  import Roles from "../tenant/Roles.svelte";
  import Policies from "../tenant/Policies.svelte";
  import RawJson from "../tenant/RawJson.svelte";
  import Members from "../tenant/Members.svelte";
  import Export from "../tenant/Export.svelte";

  let { me, name, tab }: { me: Me; name: string; tab: string | undefined } = $props();

  const CONFIG_TABS = [
    { id: "keys", label: "Keys" },
    { id: "roles", label: "Roles" },
    { id: "policies", label: "Policies" },
    { id: "raw", label: "Raw JSON" },
  ] as const;
  const OTHER_TABS: { id: string; label: string; owner: boolean }[] = [
    { id: "members", label: "Members", owner: false },
    { id: "export", label: "Export", owner: true },
  ];

  let detail = $state<TenantDetail | null>(null);
  let working = $state<Config | null>(null);
  let loadError = $state<string | null>(null);
  let saveError = $state<string | null>(null);
  let saved = $state(false);
  let saving = $state(false);
  let conflictCopy = $state<Config | null>(null);
  let rawInvalid = $state(false);

  const summary = $derived(me.tenants.find((t) => t.name === name));
  const isOwner = $derived(summary?.role === "owner");
  const suspended = $derived(detail?.status === "suspended");
  const editable = $derived(isOwner && !suspended);
  const tabs = $derived([
    ...CONFIG_TABS.map((t) => ({ ...t, owner: false })),
    ...OTHER_TABS.filter((t) => !t.owner || isOwner),
  ]);
  const current = $derived(tabs.some((t) => t.id === tab) ? (tab as string) : "keys");
  const onConfigTab = $derived(CONFIG_TABS.some((t) => t.id === current));
  const dirty = $derived(
    detail !== null && working !== null && JSON.stringify(working) !== JSON.stringify(detail.config),
  );

  async function load(): Promise<void> {
    loadError = null;
    try {
      const d = await request<TenantDetail>("GET", tenantPath(name));
      detail = d;
      working = structuredClone(d.config);
    } catch (e) {
      if (e instanceof ApiError && e.reauth) return;
      if (e instanceof ApiError && e.status === 403) {
        loadError = "You don't have permission to see this tenant.";
      } else if (e instanceof ApiError && e.status === 404) {
        loadError = "No tenant by that name.";
      } else {
        loadError = e instanceof Error ? e.message : String(e);
      }
    }
  }

  // The name as a value: the prop reads the route store, which a tab change also updates, and
  // a derived only notifies when the value itself changes.
  const tenantName = $derived(name);

  $effect(() => {
    // Reload whenever the tenant name changes; tab changes keep the working copy.
    void tenantName;
    untrack(() => {
      detail = null;
      working = null;
      conflictCopy = null;
      saveError = null;
      void load();
    });
  });

  $effect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  });

  // Members and invites only: a reload here must not throw away unsaved config edits.
  async function refreshSeats(): Promise<void> {
    const d = await request<TenantDetail>("GET", tenantPath(name));
    if (detail) detail = { ...detail, status: d.status, members: d.members, invites: d.invites };
  }

  function update(next: Config): void {
    working = next;
    saved = false;
  }

  function discard(): void {
    if (detail) working = $state.snapshot(detail.config) as Config;
    saveError = null;
  }

  async function save(): Promise<void> {
    if (!detail || !working) return;
    saving = true;
    saveError = null;
    saved = false;
    const mine = $state.snapshot(working) as Config;
    const result = await saveConfig(name, mine, detail.config_version);
    saving = false;
    if (result.ok) {
      detail = { ...detail, config: structuredClone(mine), config_version: result.version };
      conflictCopy = null;
      saved = true;
    } else if ("conflict" in result) {
      conflictCopy = mine;
      await load();
    } else if (!result.reauth) {
      saveError = result.message;
    }
  }

  function useMine(): void {
    if (conflictCopy) working = $state.snapshot(conflictCopy) as Config;
    conflictCopy = null;
  }

  const tabHref = (id: string) => `/t/${encodeURIComponent(name)}/${id}`;
</script>

<div class="space-y-4">
  <div class="flex flex-wrap items-center gap-3">
    <h1 class="text-xl font-semibold break-all">{name}</h1>
    {#if summary}<span class="badge">{summary.role}</span>{/if}
    {#if detail}
      {#if detail.status === "active"}
        <span class="badge badge-ok">active</span>
      {:else}
        <span class="badge badge-warn">suspended</span>
      {/if}
      <span class="text-xs text-muted">config version {detail.config_version}</span>
    {/if}
  </div>

  {#if loadError}
    <div class="notice notice-error" role="alert">{loadError}</div>
  {:else if !detail || !working}
    <p class="text-muted">Loading...</p>
  {:else}
    <nav class="-mx-4 overflow-x-auto border-b border-line px-4" aria-label="Tenant sections">
      <ul class="flex gap-1">
        {#each tabs as t (t.id)}
          <li>
            <a
              href={tabHref(t.id)}
              class={[
                "block border-b-2 px-3 py-2 text-sm whitespace-nowrap",
                t.id === current
                  ? "border-accent font-medium text-ink"
                  : "border-transparent text-muted hover:text-ink",
              ]}
              aria-current={t.id === current ? "page" : undefined}>{t.label}</a
            >
          </li>
        {/each}
      </ul>
    </nav>

    {#if onConfigTab}
      {#if !isOwner}
        <div class="notice notice-warn">Only owners can change the config. You can read it.</div>
      {:else if suspended}
        <div class="notice notice-warn">This tenant is suspended; its config can't change.</div>
      {/if}

      {#if conflictCopy}
        <div class="notice notice-warn space-y-2" role="alert" data-testid="conflict">
          <p class="font-medium">This config changed elsewhere.</p>
          <p>
            The editor now shows the current saved version. Your edits are below; re-enter them, or
            load them back into the editor and save over the newer version on purpose.
          </p>
          <details open>
            <summary class="cursor-pointer text-sm">Your unsaved version</summary>
            <pre
              class="mt-2 max-h-72 overflow-auto rounded border border-line bg-surface p-2 text-xs"
              data-testid="conflict-copy">{JSON.stringify(conflictCopy, null, 2)}</pre>
          </details>
          <div class="flex gap-2">
            <button type="button" class="btn" onclick={useMine}>Load my version into the editor</button>
            <button type="button" class="btn btn-quiet" onclick={() => (conflictCopy = null)}
              >Dismiss</button
            >
          </div>
        </div>
      {/if}

      {#if saveError}
        <div class="notice notice-error" role="alert" data-testid="save-error">{saveError}</div>
      {/if}

      {#if current === "keys"}
        <Keys config={working} {update} readonly={!editable} />
      {:else if current === "roles"}
        <Roles config={working} {update} readonly={!editable} audience={tenantOrigin(location.origin, name)} />
      {:else if current === "policies"}
        <Policies config={working} {update} readonly={!editable} />
      {:else if current === "raw"}
        <RawJson config={working} {update} readonly={!editable} setInvalid={(v) => (rawInvalid = v)} />
      {/if}

      {#if editable && (dirty || saved)}
        <div
          class="sticky bottom-0 -mx-4 flex flex-wrap items-center gap-3 border-t border-line bg-surface px-4 py-3"
        >
          {#if dirty}
            <span class="text-sm text-muted">Unsaved changes</span>
            <div class="ml-auto flex gap-2">
              <button type="button" class="btn" onclick={discard} disabled={saving}>Discard</button>
              <button
                type="button"
                class="btn btn-primary"
                onclick={save}
                disabled={saving || (current === "raw" && rawInvalid)}
                >{saving ? "Saving..." : "Save"}</button
              >
            </div>
          {:else}
            <span class="text-sm text-ok" role="status">Saved.</span>
          {/if}
        </div>
      {/if}
    {:else if current === "members"}
      {#if suspended}
        <div class="notice notice-warn">This tenant is suspended; its members can't change.</div>
      {/if}
      <Members
        {me}
        {name}
        members={detail.members}
        invites={detail.invites}
        {editable}
        refresh={refreshSeats}
      />
    {:else if current === "export"}
      <Export {name} config={detail.config} />
    {/if}
  {/if}
</div>
