<script lang="ts">
  import { untrack } from "svelte";
  import { cleanRole, type ClaimMatch, type Mount, type Role } from "../lib/config";
  import { actionsClaims, nameClaim, parseRepoSlug } from "../lib/actions";
  import { resolveLogin, resolveRepo, type GithubAccount, type GithubRepo } from "../lib/github";

  let {
    name: initialName = "",
    role,
    mountName,
    mountType,
    githubActions = false,
    audience = null,
    policies,
    save,
    cancel,
  }: {
    name?: string;
    role?: Role;
    mountName: string;
    mountType: Mount["type"];
    /** Whether the mount is GitHub Actions' issuer, which gets the repository preset. */
    githubActions?: boolean;
    /** The tenant's origin, the default audience for a new role on a GitHub Actions mount. */
    audience?: string | null;
    policies: string[];
    save: (name: string, role: Role) => string | null;
    cancel: () => void;
  } = $props();

  const uid = $props.id();

  interface ClaimRow {
    claim: string;
    kind: "exact" | "glob";
    value: string;
  }

  // The form edits a snapshot of the props it opened with.
  const start = untrack(() => $state.snapshot({ initialName, role, githubActions, audience }));
  const r = start.role;

  let name = $state(start.initialName);
  let chosen = $state<string[]>(r?.policies ?? []);
  let ttl = $state<number>(r?.token_ttl_secs ?? 3600);
  let notBefore = $state<number>(r?.not_before ?? 0);
  let sshKeys = $state((r?.ssh_keys ?? []).join("\n"));
  // A new role on a GitHub Actions mount starts with the tenant's own origin as its audience.
  let audiences = $state(
    r
      ? (r.bound_audiences ?? []).join("\n")
      : start.githubActions && start.audience
        ? start.audience
        : "",
  );
  let claims = $state<ClaimRow[]>(
    Object.entries(r?.bound_claims ?? {}).map(([claim, m]) =>
      typeof m === "string"
        ? { claim, kind: "exact" as const, value: m }
        : { claim, kind: "glob" as const, value: m.glob },
    ),
  );
  let users = $state<{ id: number; login?: string }[]>(
    (r?.github_user_ids ?? []).map((id) => ({ id })),
  );
  let lookup = $state("");
  let found = $state<GithubAccount | null>(null);
  let lookupError = $state<string | null>(null);
  let looking = $state(false);
  let error = $state<string | null>(null);

  // The GitHub Actions preset: a repository by name, resolved to its ids at GitHub.
  let repoSlug = $state("");
  let repoBranch = $state("");
  let repoEnvironment = $state("");
  let repo = $state<GithubRepo | null>(null);
  let repoError = $state<string | null>(null);
  let repoLooking = $state(false);

  async function findRepo(): Promise<void> {
    repo = null;
    repoError = null;
    const slug = parseRepoSlug(repoSlug);
    if (slug === null) {
      repoError = "Enter the repository as owner/repo.";
      return;
    }
    repoLooking = true;
    try {
      repo = await resolveRepo(slug.owner, slug.repo);
      if (repo === null) repoError = `No public GitHub repository ${slug.owner}/${slug.repo}.`;
    } catch (e) {
      repoError = e instanceof Error ? e.message : String(e);
    } finally {
      repoLooking = false;
    }
  }

  function useRepo(): void {
    if (!repo) return;
    const preset = actionsClaims({
      repositoryId: repo.id,
      ownerId: repo.ownerId,
      branch: repoBranch,
      environment: repoEnvironment,
    });
    // The preset's claims replace rows of the same name; other filled-in rows stay.
    const kept = claims.filter(
      (row) => !(row.claim.trim() in preset) && (row.claim.trim() !== "" || row.value !== ""),
    );
    claims = [
      ...Object.entries(preset).map(([claim, m]) =>
        typeof m === "string"
          ? { claim, kind: "exact" as const, value: m }
          : { claim, kind: "glob" as const, value: m.glob },
      ),
      ...kept,
    ];
    if (lines(audiences).length === 0 && start.audience) audiences = start.audience;
    repo = null;
  }

  const lines = (s: string) =>
    s
      .split(/[\n,]/)
      .map((l) => l.trim())
      .filter((l) => l !== "");

  async function find(): Promise<void> {
    found = null;
    lookupError = null;
    looking = true;
    try {
      const account = await resolveLogin(lookup);
      if (account === null) lookupError = `No GitHub account named ${lookup.trim()}.`;
      else found = account;
    } catch (e) {
      lookupError = e instanceof Error ? e.message : String(e);
    } finally {
      looking = false;
    }
  }

  function addFound(): void {
    if (!found) return;
    const account = found;
    if (!users.some((u) => u.id === account.id)) users = [...users, account];
    found = null;
    lookup = "";
  }

  function submit(e: SubmitEvent): void {
    e.preventDefault();
    error = null;
    if (chosen.length === 0) {
      error = "Choose at least one policy.";
      return;
    }
    const bound: Record<string, ClaimMatch> = {};
    for (const row of claims) {
      const claim = row.claim.trim();
      if (claim === "") continue;
      bound[claim] = row.kind === "glob" ? { glob: row.value } : row.value;
    }
    const built: Role = {
      mount: mountName,
      policies: policies.filter((p) => chosen.includes(p)),
      token_ttl_secs: Number(ttl),
      not_before: Number(notBefore) || 0,
      // A key line's comment may hold commas, so only newlines separate keys.
      ssh_keys: sshKeys
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l !== ""),
      bound_audiences: lines(audiences),
      bound_claims: bound,
      github_user_ids: users.map((u) => u.id),
    };
    error = save(name.trim(), cleanRole(built, mountType));
  }
</script>

<form class="space-y-4 rounded-md border border-line bg-sunken p-3" onsubmit={submit}>
  <div class="grid gap-3 sm:grid-cols-3">
    <div>
      <label class="label" for={`${uid}-name`}>Role name</label>
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
      <label class="label" for={`${uid}-ttl`}>Token lifetime (seconds)</label>
      <input
        id={`${uid}-ttl`}
        class="input"
        type="number"
        min="60"
        max="34560000"
        bind:value={ttl}
        required
      />
    </div>
    <div>
      <label class="label" for={`${uid}-nbf`}>Not before (Unix seconds)</label>
      <input id={`${uid}-nbf`} class="input" type="number" min="0" bind:value={notBefore} />
      <p class="hint">0 for none. Tokens issued earlier are refused.</p>
    </div>
  </div>

  <fieldset>
    <legend class="label">Policies</legend>
    {#if policies.length === 0}
      <p class="hint">The config has no policies yet. Add one on the Policies tab.</p>
    {/if}
    <div class="flex flex-wrap gap-x-4 gap-y-1 text-sm">
      {#each policies as p (p)}
        <label class="inline-flex items-center gap-1.5">
          <input type="checkbox" class="h-4 w-4 accent-accent" value={p} bind:group={chosen} />
          {p}
        </label>
      {/each}
    </div>
  </fieldset>

  {#if mountType === "ssh"}
    <div>
      <label class="label" for={`${uid}-ssh`}>SSH public keys, one per line</label>
      <textarea
        id={`${uid}-ssh`}
        class="input h-28 font-mono text-xs"
        bind:value={sshKeys}
        placeholder="ssh-ed25519 AAAA... you@laptop"
        spellcheck="false"
      ></textarea>
      <p class="hint">ssh-ed25519, sk-ssh-ed25519@openssh.com or ecdsa-sha2-nistp256.</p>
    </div>
  {:else if mountType === "jwt"}
    {#if start.githubActions}
      <fieldset class="space-y-2 rounded-md border border-line bg-surface p-3" data-testid="repo-preset">
        <legend class="label px-1">GitHub repository</legend>
        <p class="hint">
          Binds the repository and its owner by numeric id, which a rename or a re-registered name
          can't take over. Leave the branch and environment empty to admit every workflow in the
          repository.
        </p>
        <div class="grid gap-2 sm:grid-cols-3">
          <div>
            <label class="label" for={`${uid}-repo`}>Repository (owner/repo)</label>
            <input
              id={`${uid}-repo`}
              class="input"
              bind:value={repoSlug}
              placeholder="acme/app"
              autocomplete="off"
              spellcheck="false"
            />
          </div>
          <div>
            <label class="label" for={`${uid}-branch`}>Branch (optional)</label>
            <input
              id={`${uid}-branch`}
              class="input"
              bind:value={repoBranch}
              placeholder="main, or release/*"
              autocomplete="off"
              spellcheck="false"
            />
          </div>
          <div>
            <label class="label" for={`${uid}-env`}>Environment (optional)</label>
            <input
              id={`${uid}-env`}
              class="input"
              bind:value={repoEnvironment}
              placeholder="production"
              autocomplete="off"
              spellcheck="false"
            />
          </div>
        </div>
        <button
          type="button"
          class="btn"
          onclick={findRepo}
          disabled={repoLooking || repoSlug.trim() === ""}>Look up repository</button
        >
        {#if repo}
          <div class="flex flex-wrap items-center gap-2 text-sm" data-testid="repo-found">
            <span>
              Found <strong>{repo.fullName}</strong>: repository id {repo.id}, owner
              {repo.ownerLogin} id {repo.ownerId}.
            </span>
            <button type="button" class="btn btn-primary" onclick={useRepo}
              >Bind {repo.fullName}</button
            >
          </div>
        {/if}
        {#if repoError}
          <p class="text-sm text-danger" role="alert">{repoError}</p>
        {/if}
      </fieldset>
    {/if}
    <div>
      <label class="label" for={`${uid}-aud`}>Bound audiences, one per line</label>
      <textarea
        id={`${uid}-aud`}
        class="input h-16 font-mono text-xs"
        bind:value={audiences}
        spellcheck="false"
      ></textarea>
    </div>
    <fieldset class="space-y-2">
      <legend class="label">Bound claims</legend>
      <p class="hint">
        Every claim must match. A glob treats only * as special. Bind ids, such as repository_id
        and repository_owner_id: a name can be renamed and then taken by someone else.
      </p>
      {#each claims as row, i (i)}
        <div class="flex flex-wrap gap-2" data-testid="claim-row">
          <input
            class="input min-w-0 flex-1 basis-32"
            aria-label="Claim name"
            placeholder="claim, for example repository_id"
            bind:value={row.claim}
            spellcheck="false"
          />
          <select class="input w-auto" aria-label="Match" bind:value={row.kind}>
            <option value="exact">exact</option>
            <option value="glob">glob</option>
          </select>
          <input
            class="input min-w-0 flex-1 basis-40"
            aria-label="Claim value"
            placeholder={row.kind === "glob" ? "refs/heads/release/*" : "812345678"}
            bind:value={row.value}
            spellcheck="false"
          />
          <button
            type="button"
            class="btn btn-quiet"
            aria-label="Remove claim"
            onclick={() => (claims = claims.filter((_, j) => j !== i))}>Remove</button
          >
          {#if nameClaim(row.claim)}
            <p class="hint w-full" data-testid="name-claim">
              {row.claim.trim()} can be renamed; prefer ids.
            </p>
          {/if}
        </div>
      {/each}
      <button
        type="button"
        class="btn"
        onclick={() => (claims = [...claims, { claim: "", kind: "exact", value: "" }])}
        >Add claim</button
      >
    </fieldset>
  {:else}
    <fieldset class="space-y-2">
      <legend class="label">GitHub users</legend>
      {#if users.length > 0}
        <ul class="flex flex-wrap gap-2">
          {#each users as u (u.id)}
            <li class="badge gap-1.5">
              {u.login ?? "user"} <span class="tabular-nums">#{u.id}</span>
              <button
                type="button"
                class="cursor-pointer text-danger"
                aria-label={`Remove ${u.login ?? u.id}`}
                onclick={() => (users = users.filter((x) => x.id !== u.id))}>x</button
              >
            </li>
          {/each}
        </ul>
      {/if}
      <div class="flex flex-wrap gap-2">
        <label for={`${uid}-gh`} class="sr-only">GitHub login</label>
        <input
          id={`${uid}-gh`}
          class="input min-w-0 flex-1 basis-40"
          placeholder="GitHub login"
          bind:value={lookup}
          autocomplete="off"
          spellcheck="false"
        />
        <button type="button" class="btn" onclick={find} disabled={looking || lookup.trim() === ""}
          >Look up</button
        >
      </div>
      {#if found}
        <div class="flex flex-wrap items-center gap-2 text-sm" data-testid="found">
          <span>Found <strong>{found.login}</strong>, id {found.id}.</span>
          <button type="button" class="btn btn-primary" onclick={addFound}>Add {found.login}</button>
        </div>
      {/if}
      {#if lookupError}
        <p class="text-sm text-danger" role="alert">{lookupError}</p>
      {/if}
    </fieldset>
  {/if}

  {#if error}
    <p class="text-sm text-danger" role="alert">{error}</p>
  {/if}
  <div class="flex gap-2">
    <button type="submit" class="btn btn-primary">{start.role ? "Apply" : "Add role"}</button>
    <button type="button" class="btn" onclick={cancel}>Cancel</button>
  </div>
</form>
