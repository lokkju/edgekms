<script lang="ts">
  import {
    addMount,
    holdsAdmin,
    removeMount,
    removeRole,
    renameMount,
    setMount,
    upsertRole,
    type ClaimMatch,
    type Config,
    type Mount,
    type Role,
  } from "../lib/config";
  import { isGithubActions } from "../lib/actions";
  import Help from "../lib/Help.svelte";
  import MountForm from "./MountForm.svelte";
  import RoleForm from "./RoleForm.svelte";

  let {
    config,
    update,
    readonly,
    audience = null,
  }: {
    config: Config;
    update: (c: Config) => void;
    readonly: boolean;
    /** The tenant's origin, the default audience for a GitHub Actions role. */
    audience?: string | null;
  } = $props();

  // Which form is open: one at a time keeps the page calm on a phone.
  type Open =
    | { kind: "add-mount" }
    | { kind: "edit-mount"; name: string }
    | { kind: "add-role"; mount: string }
    | { kind: "edit-role"; name: string }
    | null;
  let open = $state<Open>(null);
  let error = $state<string | null>(null);

  const mounts = $derived(Object.entries(config.mounts));
  const policyNames = $derived(Object.keys(config.policies));
  const rolesOn = (mount: string) => Object.entries(config.roles).filter(([, r]) => r.mount === mount);
  const orphans = $derived(
    Object.entries(config.roles).filter(([, r]) => !(r.mount in config.mounts)),
  );

  function attempt(f: () => Config): string | null {
    try {
      update(f());
      open = null;
      error = null;
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : String(e);
    }
  }

  function saveNewMount(name: string, mount: Mount): string | null {
    return attempt(() => addMount(config, name, mount));
  }

  function saveMount(previous: string) {
    return (name: string, mount: Mount): string | null =>
      attempt(() => setMount(renameMount(config, previous, name), name, mount));
  }

  function saveRole(previous: string | undefined) {
    return (name: string, role: Role): string | null =>
      attempt(() => upsertRole(config, name, role, previous));
  }

  function dropMount(name: string): void {
    if (!confirm(`Remove mount ${name}?`)) return;
    error = attempt(() => removeMount(config, name));
  }

  function dropRole(name: string): void {
    const warning = holdsAdmin(config, name)
      ? `Role ${name} holds an admin policy. If it's the only way anyone can mint tokens, removing it locks that out. Remove it anyway?`
      : `Remove role ${name}?`;
    if (!confirm(warning)) return;
    error = attempt(() => removeRole(config, name));
  }

  function describeMount(m: Mount): string {
    if (m.type === "ssh") return "SSH keys";
    if (m.type === "github-user") return "GitHub users (the hosted edgekms app)";
    return m.jwks_url !== undefined ? `OIDC, issuer ${m.issuer}` : `OIDC, issuer ${m.issuer}, inline JWKS`;
  }

  function claimText(m: ClaimMatch): string {
    return typeof m === "string" ? m : `${m.glob} (glob)`;
  }
</script>

<div class="space-y-4">
  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}

  <section class="card">
    <div class="border-b border-line px-4 py-3">
      <div class="flex items-center gap-2">
        <h2 class="section-title flex-1">Mounts</h2>
        {#if !readonly && open?.kind !== "add-mount"}
          <button type="button" class="btn" onclick={() => (open = { kind: "add-mount" })}
            >Add mount</button
          >
        {/if}
      </div>
      <p class="hint" data-testid="roles-help">
        A mount is one way to log in to this tenant's keys. A role on a mount says who may log in
        that way (by token claims, SSH keys or GitHub accounts) and which policies their token
        gets. Membership doesn't grant key access; a role does.
        <Help section="roles" label="Recipes: GitHub Actions, SSH, a teammate" />
      </p>
    </div>
    {#if open?.kind === "add-mount"}
      <div class="border-b border-line p-3">
        <MountForm save={saveNewMount} cancel={() => (open = null)} />
      </div>
    {/if}
    <ul class="divide-y divide-line">
      {#each mounts as [name, mount] (name)}
        <li class="px-4 py-3" data-testid="mount" data-mount={name}>
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{name}</span>
            <span class="badge">{mount.type}</span>
            <span class="min-w-0 flex-1 text-sm break-all text-muted">{describeMount(mount)}</span>
            {#if !readonly && mount.type !== "github-user"}
              <button
                type="button"
                class="btn btn-quiet"
                onclick={() => (open = { kind: "edit-mount", name })}>Edit</button
              >
              <button type="button" class="btn btn-quiet text-danger" onclick={() => dropMount(name)}
                >Remove</button
              >
            {/if}
          </div>
          {#if mount.type === "github-user"}
            <p class="hint">Read-only: its client id must be the hosted app's.</p>
          {/if}
          {#if open?.kind === "edit-mount" && open.name === name}
            <div class="mt-3">
              <MountForm {name} {mount} save={saveMount(name)} cancel={() => (open = null)} />
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  </section>

  {#each mounts as [mountName, mount] (mountName)}
    {@const roles = rolesOn(mountName)}
    <section class="card" data-testid="role-group" data-mount={mountName}>
      <div class="flex items-center gap-2 border-b border-line px-4 py-3">
        <h2 class="section-title min-w-0 flex-1 truncate">
          Roles on <span class="font-mono">{mountName}</span>
        </h2>
        {#if !readonly && !(open?.kind === "add-role" && open.mount === mountName)}
          <button
            type="button"
            class="btn"
            onclick={() => (open = { kind: "add-role", mount: mountName })}>Add role</button
          >
        {/if}
      </div>
      {#if open?.kind === "add-role" && open.mount === mountName}
        <div class="border-b border-line p-3">
          <RoleForm
            {mountName}
            mountType={mount.type}
            githubActions={isGithubActions(mount)}
            {audience}
            policies={policyNames}
            save={saveRole(undefined)}
            cancel={() => (open = null)}
          />
        </div>
      {/if}
      {#if roles.length === 0}
        <p class="px-4 py-3 text-sm text-muted">No roles on this mount.</p>
      {/if}
      <ul class="divide-y divide-line">
        {#each roles as [roleName, role] (roleName)}
          <li class="px-4 py-3" data-testid="role" data-role={roleName}>
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium">{roleName}</span>
              {#each role.policies as p (p)}
                <span class="badge badge-accent">{p}</span>
              {/each}
              <span class="flex-1 text-xs text-muted">token {role.token_ttl_secs}s</span>
              {#if !readonly}
                <button
                  type="button"
                  class="btn btn-quiet"
                  onclick={() => (open = { kind: "edit-role", name: roleName })}>Edit</button
                >
                <button
                  type="button"
                  class="btn btn-quiet text-danger"
                  onclick={() => dropRole(roleName)}>Remove</button
                >
              {/if}
            </div>
            <dl class="mt-1 space-y-0.5 text-xs text-muted">
              {#if role.ssh_keys?.length}
                <div><dt class="inline">SSH keys:</dt> <dd class="inline">{role.ssh_keys.length}</dd></div>
              {/if}
              {#if role.bound_audiences?.length}
                <div>
                  <dt class="inline">Audiences:</dt>
                  <dd class="inline break-all">{role.bound_audiences.join(", ")}</dd>
                </div>
              {/if}
              {#each Object.entries(role.bound_claims ?? {}) as [claim, m] (claim)}
                <div>
                  <dt class="inline font-mono">{claim}</dt>
                  <dd class="inline break-all">= {claimText(m)}</dd>
                </div>
              {/each}
              {#if role.github_user_ids?.length}
                <div>
                  <dt class="inline">GitHub ids:</dt>
                  <dd class="inline">{role.github_user_ids.join(", ")}</dd>
                </div>
              {/if}
            </dl>
            {#if open?.kind === "edit-role" && open.name === roleName}
              <div class="mt-3">
                <RoleForm
                  name={roleName}
                  {role}
                  {mountName}
                  mountType={mount.type}
                  githubActions={isGithubActions(mount)}
                  {audience}
                  policies={policyNames}
                  save={saveRole(roleName)}
                  cancel={() => (open = null)}
                />
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/each}

  {#if orphans.length > 0}
    <div class="notice notice-warn">
      Roles on a mount that doesn't exist: {orphans.map(([n]) => n).join(", ")}. Fix them on the Raw
      JSON tab; the server won't accept the config as it is.
    </div>
  {/if}
</div>
