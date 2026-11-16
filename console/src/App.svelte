<script lang="ts">
  import { onMount } from "svelte";
  import {
    ApiError,
    expiryWarningDelay,
    me as fetchMe,
    sessionStartedAt,
    signOut,
    type Me,
  } from "./lib/api";
  import { route, startRouter } from "./lib/router";
  import SignIn from "./routes/SignIn.svelte";
  import RequestInvite from "./routes/RequestInvite.svelte";
  import Home from "./routes/Home.svelte";
  import NotFound from "./routes/NotFound.svelte";
  import Tenant from "./routes/Tenant.svelte";
  import Ops from "./routes/Ops.svelte";
  import Account from "./routes/Account.svelte";
  import Footer from "./lib/Footer.svelte";

  let me = $state<Me | null>(null);
  let loadError = $state<string | null>(null);
  let redirecting = $state(false);
  let signOutError = $state(false);

  onMount(startRouter);

  // A session ends 30 minutes after sign-in, however active; warn 5 minutes before. Only a page
  // load that came from a sign-in knows when that was.
  let expiring = $state(false);
  onMount(() => {
    const delay = expiryWarningDelay(sessionStartedAt(), Date.now());
    if (delay === null) return;
    const timer = setTimeout(() => (expiring = true), delay);
    return () => clearTimeout(timer);
  });

  let loading = false;

  async function loadMe(): Promise<void> {
    if (loading) return;
    loading = true;
    try {
      me = await fetchMe();
      loadError = null;
    } catch (e) {
      if (e instanceof ApiError && e.reauth) {
        redirecting = true;
        return;
      }
      loadError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  // Every page but the two public ones needs the signed-in user. The invite request page is for
  // someone sign-in just refused: loading /me there would send them straight back to GitHub.
  const PUBLIC = new Set(["signin", "request-invite"]);
  $effect(() => {
    if (!PUBLIC.has($route.name) && me === null && !redirecting) void loadMe();
  });

  async function onSignOut(): Promise<void> {
    const ok = confirm(
      "Sign out? This ends every edgekms control session you have, including the CLI's.",
    );
    if (!ok) return;
    signOutError = false;
    try {
      await signOut();
    } catch {
      signOutError = true;
      return;
    }
    me = null;
    location.assign("/signin");
  }
</script>

{#if $route.name === "signin"}
  <SignIn />
{:else if $route.name === "request-invite"}
  <RequestInvite />
{:else}
  <div class="min-h-screen">
    <header class="border-b border-line bg-surface">
      <div class="mx-auto flex max-w-5xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
        <a href="/" class="flex items-center gap-2 font-semibold">
          <img src="/favicon.svg" alt="" class="h-6 w-6" />
          <span>edgekms</span>
        </a>
        {#if me}
          <nav class="flex items-center gap-1 text-sm">
            <a href="/" class="btn btn-quiet">Tenants</a>
            {#if me.operator}
              <a href="/ops" class="btn btn-quiet">Ops</a>
            {/if}
          </nav>
          <div class="ml-auto flex items-center gap-2 text-sm">
            <span class="hidden text-muted sm:inline" data-testid="login">{me.login}</span>
            <a href="/account" class="btn btn-quiet">Account</a>
            <button type="button" class="btn" onclick={onSignOut}>Sign out</button>
          </div>
        {/if}
      </div>
    </header>

    <main class="mx-auto max-w-5xl px-4 py-6">
      {#if expiring && me}
        <div
          class="notice notice-warn mb-4 flex flex-wrap items-center gap-2"
          role="status"
          data-testid="session-expiry"
        >
          <span class="flex-1">Your session ends in 5 minutes; save your changes.</span>
          <button type="button" class="btn btn-quiet" onclick={() => (expiring = false)}
            >Dismiss</button
          >
        </div>
      {/if}
      {#if signOutError}
        <div class="notice notice-error mb-4" role="alert">
          Sign-out didn't complete; your sessions are still active. Try again.
        </div>
      {/if}
      {#if redirecting}
        <p class="text-muted">Your session ended. Taking you to sign in...</p>
      {:else if loadError}
        <div class="notice notice-error" role="alert">
          Couldn't load your account: {loadError}
          <button type="button" class="btn ml-2" onclick={loadMe}>Retry</button>
        </div>
      {:else if !me}
        <p class="text-muted">Loading...</p>
      {:else if $route.name === "home"}
        <Home {me} reload={loadMe} />
      {:else if $route.name === "ops"}
        <Ops {me} />
      {:else if $route.name === "account"}
        <Account {me} />
      {:else if $route.name === "tenant" && $route.params.name}
        <Tenant {me} name={$route.params.name} tab={$route.params.tab} />
      {:else}
        <NotFound />
      {/if}
    </main>
    <Footer />
  </div>
{/if}
