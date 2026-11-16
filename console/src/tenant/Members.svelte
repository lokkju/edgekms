<script lang="ts">
  import { ApiError, request, tenantPath, type Me, type MemberRole, type Seat } from "../lib/api";
  import { untrack } from "svelte";
  import { loginForId, resolveLogin, type GithubAccount } from "../lib/github";

  let {
    me,
    name,
    members,
    invites,
    editable,
    refresh,
  }: {
    me: Me;
    name: string;
    members: Seat[];
    invites: Seat[];
    editable: boolean;
    refresh: () => Promise<void>;
  } = $props();

  // Logins this view resolved, by id. The server keys members by id and doesn't know logins.
  let logins = $state<Record<number, string>>({});
  let lookup = $state("");
  let inviteRole = $state<MemberRole>("member");
  let found = $state<GithubAccount | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);

  // Everyone else's login, asked of GitHub by id; a failed lookup leaves the id showing.
  $effect(() => {
    const ids = [...members, ...invites].map((s) => s.github_id);
    untrack(() => {
      for (const id of ids) {
        if (id === me.github_id || id in logins) continue;
        void loginForId(id).then((login) => {
          if (login !== null && !(id in logins)) logins = { ...logins, [id]: login };
        });
      }
    });
  });

  function who(id: number): string {
    if (id === me.github_id) return `${me.login} (you)`;
    return logins[id] ?? "";
  }

  async function run(f: () => Promise<unknown>, done?: string): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await f();
      await refresh();
      if (done) notice = done;
    } catch (e) {
      if (e instanceof ApiError && e.reauth) return;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  const seatPath = (id: number) => `${tenantPath(name)}/members/${id}`;

  async function find(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    found = null;
    error = null;
    notice = null;
    busy = true;
    try {
      const account = await resolveLogin(lookup);
      if (account === null) error = `No GitHub account named ${lookup.trim()}.`;
      else found = account;
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  function sendInvite(): void {
    const account = found;
    if (!account) return;
    logins = { ...logins, [account.id]: account.login };
    void run(async () => {
      await request("PUT", seatPath(account.id), { body: { role: inviteRole } });
      found = null;
      lookup = "";
    }, `Invited ${account.login}. They accept it after signing in to the console.`);
  }

  function changeRole(seat: Seat, role: MemberRole): void {
    if (role === seat.role) return;
    const label = who(seat.github_id) || `user ${seat.github_id}`;
    const done =
      role === "owner"
        ? `${label} has an invite to become an owner; it takes effect when they accept.`
        : `${label} is now a member.`;
    void run(() => request("PUT", seatPath(seat.github_id), { body: { role } }), done);
  }

  function remove(seat: Seat, pending: boolean): void {
    const label = who(seat.github_id) || `user ${seat.github_id}`;
    const q = pending ? `Withdraw the invite to ${label}?` : `Remove ${label} from ${name}?`;
    if (!confirm(q)) return;
    void run(() => request("DELETE", seatPath(seat.github_id)));
  }
</script>

<div class="space-y-4">
  {#if error}
    <div class="notice notice-error" role="alert">{error}</div>
  {/if}
  {#if notice}
    <div class="notice notice-ok" role="status">{notice}</div>
  {/if}

  <section class="card">
    <h2 class="section-title border-b border-line px-4 py-3">Members</h2>
    <ul class="divide-y divide-line">
      {#each members as seat (seat.github_id)}
        <li class="flex flex-wrap items-center gap-3 px-4 py-3" data-testid="member">
          <div class="min-w-0 flex-1">
            <span class="font-medium">{who(seat.github_id) || "GitHub user"}</span>
            <span class="ml-1 text-sm text-muted tabular-nums">id {seat.github_id}</span>
          </div>
          {#if editable}
            <label class="sr-only" for={`role-${seat.github_id}`}>Role</label>
            <select
              id={`role-${seat.github_id}`}
              class="input w-auto"
              value={seat.role}
              disabled={busy}
              onchange={(e) => changeRole(seat, e.currentTarget.value as MemberRole)}
            >
              <option value="owner">owner</option>
              <option value="member">member</option>
            </select>
            <button
              type="button"
              class="btn btn-quiet text-danger"
              disabled={busy}
              onclick={() => remove(seat, false)}>Remove</button
            >
          {:else}
            <span class="badge">{seat.role}</span>
          {/if}
        </li>
      {/each}
    </ul>
  </section>

  <section class="card">
    <h2 class="section-title border-b border-line px-4 py-3">Pending invites</h2>
    {#if invites.length === 0}
      <p class="px-4 py-3 text-sm text-muted">No pending invites.</p>
    {/if}
    <ul class="divide-y divide-line">
      {#each invites as seat (seat.github_id)}
        <li class="flex flex-wrap items-center gap-3 px-4 py-3" data-testid="pending">
          <div class="min-w-0 flex-1">
            <span class="font-medium">{who(seat.github_id) || "GitHub user"}</span>
            <span class="ml-1 text-sm text-muted tabular-nums">id {seat.github_id}</span>
            <span class="badge ml-2">{seat.role}</span>
          </div>
          {#if editable}
            <button
              type="button"
              class="btn btn-quiet text-danger"
              disabled={busy}
              onclick={() => remove(seat, true)}>Withdraw</button
            >
          {/if}
        </li>
      {/each}
    </ul>
  </section>

  {#if editable}
    <section class="card space-y-3 p-4">
      <h2 class="section-title">Invite someone</h2>
      <p class="hint">
        Invites are by GitHub account. Making someone an owner is also an invite: it takes effect
        when they accept.
      </p>
      <form class="flex flex-col gap-2 sm:flex-row" onsubmit={find}>
        <label for="invite-login" class="sr-only">GitHub login</label>
        <input
          id="invite-login"
          class="input sm:max-w-xs"
          bind:value={lookup}
          placeholder="GitHub login"
          autocomplete="off"
          spellcheck="false"
          required
        />
        <label for="invite-role" class="sr-only">Role</label>
        <select id="invite-role" class="input sm:w-auto" bind:value={inviteRole}>
          <option value="member">member</option>
          <option value="owner">owner</option>
        </select>
        <button type="submit" class="btn" disabled={busy}>Look up</button>
      </form>
      {#if found}
        <div class="flex flex-wrap items-center gap-2 text-sm" data-testid="invite-confirm">
          <span>
            Invite <strong>{found.login}</strong> (id {found.id}) as {inviteRole}?
          </span>
          <button type="button" class="btn btn-primary" disabled={busy} onclick={sendInvite}
            >Send invite</button
          >
          <button type="button" class="btn btn-quiet" onclick={() => (found = null)}>Cancel</button>
        </div>
      {/if}
    </section>
  {/if}
</div>
