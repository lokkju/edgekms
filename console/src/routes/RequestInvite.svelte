<script lang="ts">
  // The page a sign-in refused with `signup_closed` lands on (lokkju/edgekms#12). It's public,
  // like /signin: the request cookie, not a session, is what lets it read and file the user's
  // request, and the Worker sends that cookie for the two invite request paths only.
  import Footer from "../lib/Footer.svelte";
  import { ApiError, request, type MyInviteRequest } from "../lib/api";
  import { checkNote, MAX_NOTE_CHARS, noteLength, utcDate } from "../lib/invite";

  type View =
    | { kind: "loading" }
    | { kind: "signin" }
    | { kind: "failed"; message: string }
    | { kind: "mine"; mine: MyInviteRequest };

  let view = $state<View>({ kind: "loading" });
  let note = $state("");
  let busy = $state(false);
  let serverNoteError = $state<string | null>(null);
  let refusal = $state<null | "expired" | "admitted" | "full" | "other">(null);
  let refusalMessage = $state("");

  const localNoteError = $derived(checkNote(note));
  const noteError = $derived(localNoteError ?? serverNoteError);
  const count = $derived(noteLength(note));

  /** Whether `e` says the request token is missing or no longer works. */
  function noRequestSession(e: unknown): boolean {
    return (
      e instanceof ApiError &&
      ((e.status === 401 && e.code === "no_request_session") ||
        (e.status === 403 && e.code === "auth_failed"))
    );
  }

  async function load(): Promise<void> {
    try {
      const mine = await request<MyInviteRequest>("GET", "/invite-requests/mine", {
        reauth: false,
      });
      view = { kind: "mine", mine };
    } catch (e) {
      if (noRequestSession(e)) view = { kind: "signin" };
      else view = { kind: "failed", message: e instanceof Error ? e.message : String(e) };
    }
  }

  void load();

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (view.kind !== "mine" || localNoteError !== null) return;
    const mine = view.mine;
    busy = true;
    serverNoteError = null;
    refusal = null;
    try {
      const filed = await request<{ status: "pending"; created_ms: number }>(
        "POST",
        "/invite-requests",
        { body: { note }, reauth: false },
      );
      view = {
        kind: "mine",
        mine: {
          ...mine,
          request: { status: filed.status, created_ms: filed.created_ms, decided_ms: null },
        },
      };
    } catch (err) {
      if (noRequestSession(err)) {
        refusal = "expired";
      } else if (err instanceof ApiError && err.code === "note_invalid") {
        serverNoteError = err.message;
      } else if (err instanceof ApiError && err.code === "already_admitted") {
        refusal = "admitted";
      } else if (
        err instanceof ApiError &&
        (err.code === "invite_requests_full" || err.code === "invite_requests_closed")
      ) {
        refusal = "full";
      } else if (err instanceof ApiError && err.code === "already_requested") {
        // Filed meanwhile (another tab): show it.
        await load();
      } else {
        refusal = "other";
        refusalMessage = err instanceof Error ? err.message : String(err);
      }
    } finally {
      busy = false;
    }
  }
</script>

{#snippet signInButton()}
  <a href="/auth/login?return_to=%2F" class="btn btn-primary mt-4 w-full py-2">
    Sign in with GitHub
  </a>
{/snippet}

<div class="flex min-h-screen flex-col items-center justify-center px-4">
  <div class="card w-full max-w-md p-6">
    <div class="flex items-center gap-2">
      <img src="/favicon.svg" alt="" class="h-7 w-7" />
      <h1 class="text-lg font-semibold">Request an invite</h1>
    </div>

    {#if view.kind === "loading"}
      <p class="mt-3 text-sm text-muted">Loading...</p>
    {:else if view.kind === "failed"}
      <div class="notice notice-error mt-4" role="alert">
        Couldn't load your request: {view.message}
      </div>
    {:else if view.kind === "signin"}
      <p class="mt-3 text-sm" data-testid="invite-signin">
        edgekms.dev is invite-only. Sign in with GitHub to request an invite.
      </p>
      {@render signInButton()}
      <p class="mt-3 text-sm text-muted">Already have access? You'll go straight to your tenants.</p>
    {:else if view.mine.request?.status === "pending"}
      <p class="mt-3 text-sm" data-testid="invite-pending">
        You asked for an invite on {utcDate(view.mine.request.created_ms)}. An operator will review
        it. edgekms doesn't email you: sign in again later, and once you're approved, signing in
        takes you straight to your new tenant.
      </p>
    {:else if view.mine.request?.status === "approved"}
      <p class="mt-3 text-sm" data-testid="invite-approved">
        Your request was approved. Sign in to get started.
      </p>
      {@render signInButton()}
    {:else if view.mine.request?.status === "declined"}
      <p class="mt-3 text-sm" data-testid="invite-declined">
        Your request on {utcDate(view.mine.request.created_ms)} wasn't approved.
      </p>
    {:else if !view.mine.accepting}
      <p class="mt-3 text-sm" data-testid="invite-closed">
        We're not taking invite requests right now.
      </p>
    {:else}
      <form class="mt-3 space-y-3" onsubmit={submit} data-testid="invite-form">
        <p class="text-sm">Signed in with GitHub as <strong>{view.mine.login}</strong>.</p>
        <div>
          <label for="invite-note" class="text-sm font-medium"
            >What will you use edgekms for? (optional)</label
          >
          <textarea
            id="invite-note"
            class="input mt-1 min-h-28 w-full"
            bind:value={note}
            oninput={() => (serverNoteError = null)}
            aria-invalid={noteError !== null}
            aria-describedby="invite-note-count"
          ></textarea>
          <div class="mt-1 flex items-start gap-2 text-xs">
            {#if noteError}
              <span class="flex-1 text-danger" data-testid="note-error">{noteError}</span>
            {:else}
              <span class="flex-1"></span>
            {/if}
            <span
              id="invite-note-count"
              class="tabular-nums {count > MAX_NOTE_CHARS ? 'text-danger' : 'text-muted'}"
              data-testid="note-count">{count} / {MAX_NOTE_CHARS}</span
            >
          </div>
        </div>
        {#if refusal === "expired"}
          <div class="notice notice-warn" role="alert" data-testid="invite-expired">
            Your sign-in for this request expired. Copy your note, then sign in again.
          </div>
          {@render signInButton()}
        {:else if refusal === "admitted"}
          <div class="notice notice-ok" role="status" data-testid="invite-admitted">
            You can sign in now.
          </div>
          {@render signInButton()}
        {:else if refusal === "full"}
          <div class="notice notice-warn" role="alert">
            We're not taking more requests right now. Try again later.
          </div>
        {:else if refusal === "other"}
          <div class="notice notice-error" role="alert">{refusalMessage}</div>
        {/if}
        {#if refusal !== "expired" && refusal !== "admitted"}
          <button
            type="submit"
            class="btn btn-primary w-full py-2"
            disabled={busy || localNoteError !== null}>Request an invite</button
          >
        {/if}
      </form>
    {/if}
  </div>
  <Footer />
</div>
