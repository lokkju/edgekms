// The messages for `/signin?error=<code>`. The Worker sends only these codes.

export const SIGNIN_MESSAGES: Record<string, string> = {
  state: "That sign-in didn't complete, or it was already used. Sign in again.",
  github_denied:
    "GitHub didn't authorize the sign-in. Sign in again and approve the edgekms app when GitHub asks.",
  signup_closed:
    "edgekms isn't taking new signups right now. If someone invited you to a tenant, sign in again after they send the invite.",
  rate_limited: "Too many sign-in attempts from your network. Wait a few minutes and try again.",
  login_failed: "Sign-in failed on our side. Try again in a moment.",
};

export function signInMessage(code: string): string {
  return SIGNIN_MESSAGES[code] ?? "Sign-in failed. Try again.";
}
