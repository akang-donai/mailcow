// src/remote/consent.ts
//
// The consent page is the gate that turns "someone completed an OAuth dance"
// into "someone proved they control this mailbox". It renders attacker-
// influenceable values (the handle echoed from the query/form, and the
// mailbox the visitor typed) into HTML, so every interpolated value MUST be
// escaped -- including inside attribute contexts, where an unescaped quote
// character would let a value break out of value="...". The app password is
// never interpolated anywhere, including on the error re-render path: if a
// mistyped password causes the form to come back, the password field is
// rendered empty.
import { randomToken } from './crypto.ts';
import type { PendingStore, CredentialStore, SqliteClientsStore } from './store.ts';
import type { MailcowOAuthProvider } from './provider.ts';
import type { ImapVerifier } from './verify.ts';

export type ConsentDeps = {
  pending: PendingStore;
  credentials: CredentialStore;
  provider: MailcowOAuthProvider;
  clientsStore: SqliteClientsStore;
  verify: ImapVerifier;
  imapHost: string;
  imapPort: number;
};

const ESCAPE_MAP: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ESCAPE_MAP[c]!);

// `mailbox` is only ever the value to redisplay in the form -- it is never
// used to decide anything security-relevant here, so passing an empty
// default when there's nothing to prefill is safe.
export function renderConsent(handle: string, error?: string, mailbox = ''): string {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect your mailbox</title>
</head>
<body style="font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem">
<h1>Connect your mailbox</h1>
<p>Enter your mailbox address and an <strong>IMAP-only app password</strong> created in mailcow. This grants Claude read-only access to your mail.</p>
${error ? `<p style="color:#b00" role="alert">${esc(error)}</p>` : ''}
<form method="post" action="/consent">
<input type="hidden" name="handle" value="${esc(handle)}">
<label>Mailbox<br><input name="mailbox" type="email" required value="${esc(mailbox)}" style="width:100%"></label><br><br>
<label>App password<br><input name="app_password" type="password" required autocomplete="off" style="width:100%"></label><br><br>
<button type="submit">Authorise</button>
</form>
</body>
</html>`;
}

export function beginConsent(
  deps: ConsentDeps,
  p: { clientId: string; redirectUri: string; codeChallenge: string; state?: string; resource?: string; scopes?: string[] },
): string {
  const handle = randomToken();
  deps.pending.save(handle, { ...p, ttlSec: 600 });
  return `/consent?handle=${encodeURIComponent(handle)}`;
}

export async function handleConsent(
  deps: ConsentDeps,
  body: { handle?: string; mailbox?: string; app_password?: string },
): Promise<{ redirectTo: string } | { rerender: string }> {
  const handle = body.handle ?? '';

  // Single-use + expiring: PendingStore.get() itself rejects an expired row,
  // and a handle that has already been consumed was deleted by a prior call
  // to this function -- so both an expired and a replayed handle land here.
  const pending = deps.pending.get(handle);
  if (!pending) {
    return { rerender: renderConsent(handle, 'This authorisation request has expired or was already used. Start again from Claude.') };
  }

  const mailbox = (body.mailbox ?? '').trim().toLowerCase();
  const appPassword = body.app_password ?? '';
  if (!mailbox || !appPassword) {
    return { rerender: renderConsent(handle, 'Both fields are required.', mailbox) };
  }

  // The credential must be proven before anything is stored or issued: no
  // store, no code, on a failed verification.
  const ok = await deps.verify(deps.imapHost, deps.imapPort, mailbox, appPassword);
  if (!ok) {
    return { rerender: renderConsent(handle, 'Could not sign in to that mailbox with that app password.', mailbox) };
  }

  const client = deps.clientsStore.getClient(pending.clientId);
  if (!client) {
    return { rerender: renderConsent(handle, 'Unknown client. Start again from Claude.', mailbox) };
  }

  deps.credentials.put(mailbox, deps.imapHost, deps.imapPort, appPassword);

  const code = deps.provider.completeAuthorization({
    client,
    subject: mailbox,
    params: {
      codeChallenge: pending.codeChallenge,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes,
      resource: pending.resource,
    },
  });

  // Delete only after everything has succeeded, so a failure earlier in this
  // function leaves the handle intact and retryable.
  deps.pending.delete(handle);

  // The redirect target comes ONLY from the pending row saved at
  // authorization time -- never from the consent POST body -- so a
  // malicious body field can't turn this into an open redirect / token
  // theft path.
  const redirect = new URL(pending.redirectUri);
  redirect.searchParams.set('code', code);
  if (pending.state) redirect.searchParams.set('state', pending.state);
  return { redirectTo: redirect.href };
}
