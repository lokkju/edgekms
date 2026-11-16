<script lang="ts">
  import {
    ApiError,
    request,
    type Allowlist,
    type InviteRequest,
    type InviteRequestList,
    type Me,
    type TenantStatus,
  } from "../lib/api";
  import { untrack } from "svelte";
  import {
    accountById,
    loginForId,
    resolveLogin,
    type GithubAccount,
    type GithubProfile,
  } from "../lib/github";

  /** GitHub allows 60 unauthenticated lookups an hour per IP; the queue gets at most half. */
  const MAX_LOOKUPS = 30;
  const DAY_MS = 86_400_000;

  let { me }: { me: Me } = $props();

  let list = $state<Allowlist | null>(null);
  let requests = $state<InviteRequestList | null>(null);
  let profiles = $state<Record<number, GithubProfile>>({});
  let showDecided = $state(false);
  let logins = $state<Record<number, string>>({});
  let lookup = $state("");
  let found = $state<GithubAccount | null>(null);
  let tenant = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);

  function fail(e: unknown): void {
    if (e instanceof ApiError && e.reauth) return;
    error = e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    try {
      list = await request<Allowlist>("GET", "/ops/allowlist");
    } catch (e) {
      fail(e);
    }
  }

  async function loadRequests(): Promise<void> {
    try {
      requests = await request<InviteRequestList>("GET", "/ops/invite-requests");
    } catch (e) {
      fail(e);
    }
  }

  $effect(() => {
    if (me.operator) {
      void load();
      void loadRequests();
    }
  });

  const pendingRequests = $derived(requests?.requests.filter((r) => r.status === "pending") ?? []);
  const decidedRequests = $derived(requests?.requests.filter((r) => r.status !== "pending") ?? []);

  // The GitHub account behind each of the first pending requests: current login, age and public
  // repos, for the operator to judge by. A failed lookup leaves the row without them.
  $effect(() => {
    const ids = pendingRequests.slice(0, MAX_LOOKUPS).map((r) => r.github_id);
    untrack(() => {
      for (const id of ids) {
        if (id in profiles) continue;
        void accountById(id).then((p) => {
          if (p !== null && !(id in profiles)) profiles = { ...profiles, [id]: p };
        });
      }
    });
  });

  function decide(r: InviteRequest, action: "approve" | "decline"): void {
    const verb = action === "approve" ? "Approve" : "Decline";
    const what =
      action === "approve"
        ? `${verb} ${r.login}'s request? They'll be on the signup allowlist, and their next sign-in creates their tenant.`
        : `${verb} ${r.login}'s request? They can't ask again unless you delete the request.`;
    if (!confirm(what)) return;
    void run(
      async () => {
        await request("POST", `/ops/invite-requests/${r.github_id}/${action}`, { body: {} });
        logins = { ...logins, [r.github_id]: r.login };
        await Promise.all([loadRequests(), load()]);
      },
      action === "approve" ? `${r.login} can sign up now.` : `Declined ${r.login}'s request.`,
    );
  }

  function deleteRequest(id: number): void {
    if (!confirm("Delete this request? A declined user can then request again.")) return;
    void run(async () => {
      await request("DELETE", `/ops/invite-requests/${id}`, { body: {} });
      await loadRequests();
    }, "Deleted the request.");
  }

  /** "declined 2025-11-11 by id 1001", from what the row records. */
  function decision(r: InviteRequest): string {
    const when = r.decided_ms === null ? "" : ` ${date(r.decided_ms)}`;
    const by = r.decided_by === null ? "" : ` by id ${r.decided_by}`;
    return `${r.status}${when}${by}`;
  }

  const ageDays = (ms: number) => Math.max(0, Math.floor((Date.now() - ms) / DAY_MS));

  // Logins for the allowlist's ids, asked of GitHub; a failed lookup leaves the id showing.
  $effect(() => {
    const ids = list?.allowlist.map((e) => e.github_id) ?? [];
    untrack(() => {
      for (const id of ids) {
        if (id in logins) continue;
        if (id === me.github_id) {
          logins = { ...logins, [id]: me.login };
          continue;
        }
        void loginForId(id).then((login) => {
          if (login !== null && !(id in logins)) logins = { ...logins, [id]: login };
        });
      }
    });
  });

  async function run(f: () => Promise<unknown>, done: string): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await f();
      notice = done;
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function find(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    found = null;
    error = null;
    notice = null;
    try {
      const account = await resolveLogin(lookup);
      if (account === null) error = `No GitHub account named ${lookup.trim()}.`;
      else found = account;
    } catch (err) {
      fail(err);
    }
  }

  function allow(): void {
    const account = found;
    if (!account) return;
    logins = { ...logins, [account.id]: account.login };
    void run(async () => {
      await request("PUT", `/ops/allowlist/${account.id}`, { body: {} });
      found = null;
      lookup = "";
      await load();
    }, `${account.login} can sign up now.`);
  }

  function disallow(id: number): void {
    const label = logins[id] ?? `user ${id}`;
    if (!confirm(`Remove ${label} from the signup allowlist?`)) return;
    void run(async () => {
      await request("DELETE", `/ops/allowlist/${id}`, { body: {} });
      await load();
    }, `${label} is off the allowlist.`);
  }

  function setStatus(e: Event, status: TenantStatus): void {
    e.preventDefault();
    const name = tenant.trim();
    if (name === "") return;
    const verb = status === "suspended" ? "Suspend" : "Resume";
    if (!confirm(`${verb} tenant ${name}?`)) return;
    void run(
      () => request("PUT", `/ops/tenants/${encodeURIComponent(name)}/status`, { body: { status } }),
      `${name} is ${status === "suspended" ? "suspended" : "active"}.`,
    );
  }

  const date = (ms: number) => new Date(ms).toISOString().slice(0, 10);
</script>

{#if !me.operator}
  <div class="notice notice-warn">This page is for operators.</div>
{:else}
  <div class="space-y-4">
    <h1 class="text-xl font-semibold">Operations</h1>
    {#if error}
      <div class="notice notice-error" role="alert">{error}</div>
    {/if}
    {#if notice}
      <div class="notice notice-ok" role="status">{notice}</div>
    {/if}

    <section class="card">
      <div class="border-b border-line px-4 py-3">
        <h2 class="section-title">Invite requests ({requests?.pending ?? 0} pending)</h2>
        <p class="hint">
          People GitHub sign-in refused who asked for an invite. Approving puts them on the signup
          allowlist below.
        </p>
      </div>
      {#if requests === null}
        <p class="px-4 py-3 text-sm text-muted">Loading...</p>
      {:else}
        {#if pendingRequests.length === 0}
          <p class="px-4 py-3 text-sm text-muted">No pending requests.</p>
        {/if}
        <ul class="divide-y divide-line">
          {#each pendingRequests as r (r.github_id)}
            {@const p = profiles[r.github_id]}
            <li class="space-y-2 px-4 py-3" data-testid="invite-request">
              <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span class="font-medium">{r.login}</span>
                <span class="text-sm text-muted tabular-nums">id {r.github_id}</span>
                <span class="text-xs text-muted">requested {date(r.created_ms)}</span>
                {#if p}
                  {#if p.login !== r.login}
                    <span class="text-xs text-muted">now @{p.login}</span>
                  {/if}
                  {#if p.createdMs !== null}
                    <span class="text-xs text-muted">
                      account created {date(p.createdMs)}, {ageDays(p.createdMs)} days old
                    </span>
                  {/if}
                  {#if p.publicRepos !== null}
                    <span class="text-xs text-muted">{p.publicRepos} public repos</span>
                  {/if}
                {/if}
              </div>
              {#if r.note !== ""}
                <p
                  class="whitespace-pre-wrap wrap-anywhere rounded-md bg-sunken px-3 py-2 text-sm"
                  data-testid="invite-note">{r.note}</p>
              {/if}
              <div class="flex gap-2">
                <button
                  type="button"
                  class="btn btn-primary"
                  disabled={busy}
                  onclick={() => decide(r, "approve")}>Approve</button
                >
                <button
                  type="button"
                  class="btn"
                  disabled={busy}
                  onclick={() => decide(r, "decline")}>Decline</button
                >
              </div>
            </li>
          {/each}
        </ul>
        {#if requests.unverified.length > 0}
          <div class="notice notice-warn mx-4 mb-3 space-y-2" data-testid="unverified-requests">
            <p>
              Requests that don't verify, so they can't be approved: {requests.unverified.join(", ")}.
            </p>
            <div class="flex flex-wrap gap-2">
              {#each requests.unverified as id (id)}
                <button
                  type="button"
                  class="btn btn-quiet text-danger"
                  disabled={busy}
                  onclick={() => deleteRequest(id)}>Delete {id}</button
                >
              {/each}
            </div>
          </div>
        {/if}
        {#if decidedRequests.length > 0}
          <div class="border-t border-line px-4 py-3">
            <button
              type="button"
              class="btn btn-quiet"
              aria-expanded={showDecided}
              onclick={() => (showDecided = !showDecided)}
              >{showDecided ? "Hide decided" : "Show decided"}</button
            >
          </div>
          {#if showDecided}
            <ul class="divide-y divide-line border-t border-line">
              {#each decidedRequests as r (r.github_id)}
                <li class="flex flex-wrap items-center gap-3 px-4 py-3" data-testid="decided-request">
                  <div class="min-w-0 flex-1">
                    <span class="font-medium">{r.login}</span>
                    <span class="ml-1 text-sm text-muted tabular-nums">id {r.github_id}</span>
                    <span class="ml-2 text-xs text-muted">{decision(r)}</span>
                  </div>
                  <button
                    type="button"
                    class="btn btn-quiet text-danger"
                    disabled={busy}
                    onclick={() => deleteRequest(r.github_id)}>Delete</button
                  >
                </li>
              {/each}
            </ul>
          {/if}
        {/if}
      {/if}
    </section>

    <section class="card">
      <div class="border-b border-line px-4 py-3">
        <h2 class="section-title">Signup allowlist</h2>
        <p class="hint">Who may create a personal tenant while signups are invite-only.</p>
      </div>
      {#if list === null}
        <p class="px-4 py-3 text-sm text-muted">Loading...</p>
      {:else}
        {#if list.allowlist.length === 0}
          <p class="px-4 py-3 text-sm text-muted">Nobody is on the allowlist.</p>
        {/if}
        <ul class="divide-y divide-line">
          {#each list.allowlist as entry (entry.github_id)}
            <li class="flex flex-wrap items-center gap-3 px-4 py-3" data-testid="allow-entry">
              <div class="min-w-0 flex-1">
                <span class="font-medium">{logins[entry.github_id] ?? "GitHub user"}</span>
                <span class="ml-1 text-sm text-muted tabular-nums">id {entry.github_id}</span>
                <span class="ml-2 text-xs text-muted">
                  added {date(entry.added_ms)} by id {entry.added_by}
                </span>
              </div>
              <button
                type="button"
                class="btn btn-quiet text-danger"
                disabled={busy}
                onclick={() => disallow(entry.github_id)}>Remove</button
              >
            </li>
          {/each}
        </ul>
        {#if list.unverified.length > 0}
          <div class="notice notice-warn mx-4 mb-3">
            Rows that don't verify, so they admit nobody: {list.unverified.join(", ")}.
          </div>
        {/if}
      {/if}
      <form class="flex flex-col gap-2 border-t border-line px-4 py-3 sm:flex-row" onsubmit={find}>
        <label for="allow-login" class="sr-only">GitHub login</label>
        <input
          id="allow-login"
          class="input sm:max-w-xs"
          bind:value={lookup}
          placeholder="GitHub login"
          autocomplete="off"
          spellcheck="false"
          required
        />
        <button type="submit" class="btn" disabled={busy}>Look up</button>
      </form>
      {#if found}
        <div class="flex flex-wrap items-center gap-2 px-4 pb-3 text-sm">
          <span>Allow <strong>{found.login}</strong> (id {found.id}) to sign up?</span>
          <button type="button" class="btn btn-primary" disabled={busy} onclick={allow}>Allow</button>
          <button type="button" class="btn btn-quiet" onclick={() => (found = null)}>Cancel</button>
        </div>
      {/if}
    </section>

    <section class="card space-y-3 p-4">
      <div>
        <h2 class="section-title">Suspend or resume a tenant</h2>
        <p class="hint">
          A suspended tenant's host refuses every request, and its config and members can't
          change; its owners can still export. Operators can't list tenants they don't belong to,
          so type the name.
        </p>
      </div>
      <form class="flex flex-col gap-2 sm:flex-row" onsubmit={(e) => setStatus(e, "suspended")}>
        <label for="status-tenant" class="sr-only">Tenant name</label>
        <input
          id="status-tenant"
          class="input sm:max-w-xs"
          bind:value={tenant}
          placeholder="tenant name"
          autocomplete="off"
          spellcheck="false"
          required
        />
        <button type="submit" class="btn btn-danger" disabled={busy}>Suspend</button>
        <button
          type="button"
          class="btn"
          disabled={busy || tenant.trim() === ""}
          onclick={(e) => setStatus(e, "active")}>Resume</button
        >
      </form>
    </section>
  </div>
{/if}
