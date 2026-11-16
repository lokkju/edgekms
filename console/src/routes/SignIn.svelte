<script lang="ts">
  import Footer from "../lib/Footer.svelte";
  import { signInMessage } from "../lib/signin";

  const code = new URLSearchParams(location.search).get("error");
  const message = code === null ? null : signInMessage(code);
</script>

<div class="flex min-h-screen flex-col items-center justify-center px-4">
  <div class="card w-full max-w-sm p-6">
    <div class="flex items-center gap-2">
      <img src="/favicon.svg" alt="" class="h-7 w-7" />
      <h1 class="text-lg font-semibold">edgekms console</h1>
    </div>
    <p class="mt-3 text-sm text-muted">
      Manage your tenants, keys, roles and members. You sign in with your GitHub account.
    </p>
    {#if message}
      <div class="notice notice-error mt-4" role="alert" data-testid="signin-error">{message}</div>
    {/if}
    <a href="/auth/login?return_to=%2F" class="btn btn-primary mt-5 w-full py-2">
      Sign in with GitHub
    </a>
  </div>
  <Footer />
</div>
