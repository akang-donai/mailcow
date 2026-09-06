// src/remote/consent.ts
//
// The consent page is the gate that turns "someone completed an OAuth dance"
// into "someone proved they control this mailbox". It renders attacker-
// influenceable values (the handle echoed from the query/form, the mailbox
// the visitor typed, and -- since dynamic client registration is open by
// design -- the requesting client's own name and redirect URI) into HTML,
// so every interpolated value MUST be escaped, including inside attribute
// contexts where an unescaped quote would let a value break out of
// value="...". The app password is never interpolated anywhere, including
// on the error re-render path: if a mistyped password causes the form to
// come back, the password field is rendered empty.
//
// Two properties beyond escaping matter here, because the page is the only
// thing standing between a rogue client and a victim's mailbox:
//
//   1. IDENTIFICATION. Anyone can register a client (that is what DCR is)
//      and choose its client_name and redirect_uri. The page therefore
//      names the actual requesting client and, prominently, the origin the
//      browser will be sent to afterwards -- the one part of a registration
//      an attacker cannot forge into looking like somebody else. It must
//      not claim the request came from "Claude"; it previously did, on a
//      page served with the genuine host's certificate, which is precisely
//      what made a rogue-client phish convincing.
//
//   2. BROWSER BINDING. The pending handle is a bearer value. Without
//      binding it to the browser that started the flow, an attacker can run
//      /authorize themselves and hand the resulting consent link to a
//      victim, who then types their app password into a legitimate-looking
//      page and mints a code for the ATTACKER's redirect_uri. beginConsent
//      therefore sets an HttpOnly/Secure/SameSite=Lax cookie scoped to
//      /consent, and POST /consent requires it to match.
import { randomToken, hashToken, timingSafeEqualHex } from './crypto.ts';
import { scopeVerdict, type SmtpProbe } from '../smtp-check.ts';
import type { PendingStore, CredentialStore, SqliteClientsStore, TokenStore } from './store.ts';
import type { MailcowOAuthProvider } from './provider.ts';
import type { ImapVerifier } from './verify.ts';

export type ConsentDeps = {
  pending: PendingStore;
  credentials: CredentialStore;
  provider: MailcowOAuthProvider;
  clientsStore: SqliteClientsStore;
  tokens: TokenStore;
  verify: ImapVerifier;
  imapHost: string;
  imapPort: number;
  smtpProbe: SmtpProbe;
  smtpHost: string;
  smtpPort: number;
};

// The narrowest slice of express.Response beginConsent needs. Declared
// structurally so this module stays testable without an HTTP server.
export type CookieSetter = {
  cookie(name: string, value: string, options: Record<string, unknown>): unknown;
  clearCookie?(name: string, options: Record<string, unknown>): unknown;
};

export const CONSENT_COOKIE = 'mailcp_consent';

// Path-scoped so it is never sent to /mcp, /token or anything else; Lax
// rather than Strict because the browser arrives at /consent via a
// cross-site redirect from the client's own /authorize call, which Strict
// would drop. Not a __Host- prefix: that mandates Path=/, which would
// broaden the cookie to every route on the origin.
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' as const,
  path: '/consent',
  maxAge: 600_000,
};

const ESCAPE_MAP: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ESCAPE_MAP[c]!);

const UNKNOWN_CLIENT = 'an unidentified application';
const UNKNOWN_DESTINATION = '(unknown)';

export type ConsentView = {
  handle: string;
  /** The requesting client's registered name. Attacker-chosen; escaped, never trusted. */
  clientName: string;
  /** Origin of the registered redirect_uri. Attacker-chosen but not forgeable as someone else's. */
  redirectOrigin: string;
  error?: string;
  /** Only ever the value to redisplay in the form; never used to decide anything. */
  mailbox?: string;
};

/**
 * The origin a successful consent will send the browser to.
 *
 * Custom-scheme redirect URIs (com.example.app://cb) serialise to the string
 * "null" as an origin, which tells a reader nothing -- show the whole URI in
 * that case instead. Either way the result is escaped before rendering.
 */
export function redirectDestination(redirectUri: string): string {
  try {
    const url = new URL(redirectUri);
    return url.origin && url.origin !== 'null' ? url.origin : redirectUri;
  } catch {
    return redirectUri || UNKNOWN_DESTINATION;
  }
}

/** Everything the page needs to identify the requester, resolved from a handle. */
export function consentView(deps: ConsentDeps, handle: string): ConsentView {
  const pending = deps.pending.get(handle);
  if (!pending) return { handle, clientName: UNKNOWN_CLIENT, redirectOrigin: UNKNOWN_DESTINATION };
  const client = deps.clientsStore.getClient(pending.clientId);
  return {
    clientName: client?.client_name || UNKNOWN_CLIENT,
    redirectOrigin: redirectDestination(pending.redirectUri),
    handle,
  };
}

export function renderConsent(v: ConsentView): string {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect your mailbox</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 30rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
.dest { display: block; margin: .5rem 0 1rem; padding: .75rem 1rem; border: 2px solid #333; border-radius: .4rem;
        font-family: ui-monospace, monospace; font-size: 1.15rem; font-weight: 700; word-break: break-all; }
.who { font-size: 1.05rem; }
.warn { color: #6b4d00; background: #fff8e1; border-left: 4px solid #c79100; padding: .6rem .8rem; font-size: .92rem; }
.err { color: #b00; }
label { display: block; margin-bottom: 1rem; }
input { width: 100%; box-sizing: border-box; padding: .4rem; font-size: 1rem; }
</style>
</head>
<body>
<h1>Connect your mailbox</h1>
<p class="who">The application <strong>${esc(v.clientName)}</strong> is asking for read-only access to your mailbox.</p>
<p>If you continue, your browser will be sent to:</p>
<code class="dest">${esc(v.redirectOrigin)}</code>
<p class="warn">Anyone can register an application with this server and choose the name shown above, so the name proves nothing. The address in the box is the part they cannot fake. <strong>Stop now</strong> if you did not start this from that application.</p>
${v.error ? `<p class="err" role="alert">${esc(v.error)}</p>` : ''}
<form method="post" action="/consent">
<input type="hidden" name="handle" value="${esc(v.handle)}">
<label>Mailbox<br><input name="mailbox" type="email" required value="${esc(v.mailbox ?? '')}"></label>
<label>App password (an <strong>IMAP-only</strong> app password created in mailcow)<br><input name="app_password" type="password" required autocomplete="off"></label>
<button type="submit">Authorise</button>
</form>
</body>
</html>`;
}

/**
 * Start a consent flow: store the pending authorization, bind it to this
 * browser with a cookie, and return the URL to redirect to.
 *
 * The cookie is set here rather than by the caller so the binding cannot be
 * accidentally separated from the handle it protects.
 */
export function beginConsent(
  deps: ConsentDeps,
  res: CookieSetter,
  p: { clientId: string; redirectUri: string; codeChallenge: string; state?: string; resource?: string; scopes?: string[] },
): string {
  const handle = randomToken();
  // A second, independent secret. The handle travels in a URL (logs,
  // Referer, shoulder-surfing); this one only ever travels in a
  // path-scoped HttpOnly cookie, so holding the URL is not enough.
  const browserToken = randomToken();
  deps.pending.save(handle, { ...p, browserToken, ttlSec: 600 });
  res.cookie(CONSENT_COOKIE, browserToken, COOKIE_OPTIONS);
  return `/consent?handle=${encodeURIComponent(handle)}`;
}

/** Pull the consent binding value out of a raw Cookie header. */
export function readConsentCookie(header: string | undefined): string {
  if (typeof header !== 'string') return '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== CONSENT_COOKIE) continue;
    const raw = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  return '';
}

export async function handleConsent(
  deps: ConsentDeps,
  body: { handle?: string; mailbox?: string; app_password?: string },
  browserToken: string,
  res?: CookieSetter,
): Promise<{ redirectTo: string } | { rerender: string }> {
  // The declared parameter type is a compile-time shape only -- Node strips
  // types without checking them at runtime, and a real HTTP request is not
  // obligated to match it. In particular, a duplicated form field (e.g. two
  // `handle=` values in an urlencoded POST body) is turned into an ARRAY by
  // a typical body parser, and nothing stops a caller from sending a number,
  // null, or an object either. Every field is therefore checked with
  // `typeof === 'string'` before use; anything else is treated as
  // absent/invalid and routed through the same `{ rerender }` path already
  // used for a missing field. This is deliberately NOT "take the first
  // element of the array" -- a duplicated field is a malformed request, not
  // a hint about which value to trust.
  const handle = typeof body.handle === 'string' ? body.handle : '';

  // Single-use + expiring: PendingStore.get() itself rejects an expired row,
  // and a handle that has already been consumed was deleted by a prior call
  // to this function -- so both an expired and a replayed handle land here.
  // A non-string handle also lands here, since it becomes '' above and no
  // real pending row is ever stored under an empty handle.
  const pending = deps.pending.get(handle);
  if (!pending) {
    return {
      rerender: renderConsent({
        handle,
        clientName: UNKNOWN_CLIENT,
        redirectOrigin: UNKNOWN_DESTINATION,
        error: 'This authorisation request has expired or was already used. Start again from the application you are connecting.',
      }),
    };
  }

  const view = consentView(deps, handle);

  // Browser binding. Without this, an attacker runs /authorize in THEIR
  // browser, sends the victim the resulting /consent link, and the victim's
  // app password mints a code that redirects to the attacker's own
  // redirect_uri. A missing cookie and a wrong cookie are the same answer.
  const expected = pending.browserTokenHash;
  if (!expected || typeof browserToken !== 'string' || !browserToken || !timingSafeEqualHex(hashToken(browserToken), expected)) {
    return {
      rerender: renderConsent({
        ...view,
        error:
          'This authorisation request was not started in this browser, so it cannot be completed here. Start the connection again from the application itself, in this browser.',
      }),
    };
  }

  const mailboxInput = typeof body.mailbox === 'string' ? body.mailbox : '';
  const mailbox = mailboxInput.trim().toLowerCase();
  const appPassword = typeof body.app_password === 'string' ? body.app_password : '';
  if (!mailbox || !appPassword) {
    return { rerender: renderConsent({ ...view, error: 'Both fields are required.', mailbox }) };
  }

  // The credential must be proven before anything is stored or issued: no
  // store, no code, on a failed verification.
  const ok = await deps.verify(deps.imapHost, deps.imapPort, mailbox, appPassword);
  if (!ok) {
    return { rerender: renderConsent({ ...view, error: 'Could not sign in to that mailbox with that app password.', mailbox }) };
  }

  // Scope check. The design puts sending out of scope on the grounds that
  // the credentials are "scoped to imap_access, verified by
  // scripts/check-no-smtp.ts" -- but that script reads Step A's accounts
  // file and has no access to these encrypted per-subject rows. Nothing
  // checked scope here, so a user who pasted their FULL mailbox password
  // was enrolled and the database then held a send-capable credential:
  // exactly the outcome the design rejected as "the worst outcome under
  // breach".
  //
  // Only a SUCCESSFUL SMTP AUTH refuses the enrolment. Anything else --
  // refused, unparseable, or no SMTP endpoint reachable at all -- lets it
  // through, because a mailcow with SMTP disabled or firewalled must not
  // block every enrolment on the domain. The inconclusive case is logged so
  // it is visible rather than silently permissive.
  //
  // The IMAP login above is a precondition, not a convenience: a wrong
  // password is refused by SMTP too, and would otherwise look perfectly
  // scoped. That is why scopeVerdict takes both legs.
  let smtp: Awaited<ReturnType<SmtpProbe>>;
  try {
    smtp = await deps.smtpProbe(deps.smtpHost, deps.smtpPort, mailbox, appPassword);
  } catch {
    // A probe is contracted not to throw, but a thrown probe must be
    // inconclusive rather than an unhandled rejection that 500s the form.
    smtp = 'unknown';
  }
  const verdict = scopeVerdict(true, smtp);
  if (verdict === 'can-send') {
    return {
      rerender: renderConsent({
        ...view,
        error:
          'That app password can also SEND mail, so it will not be accepted. In mailcow, create a new app password with only "imap_access" ticked (not "smtp_access"), and use that instead. This connector only ever reads.',
        mailbox,
      }),
    };
  }
  if (verdict === 'inconclusive') {
    console.warn(
      `mailcp consent: SMTP scope check inconclusive for ${mailbox} via ${deps.smtpHost}:${deps.smtpPort} -- enrolling anyway, this credential's send capability is UNVERIFIED`,
    );
  }

  const client = deps.clientsStore.getClient(pending.clientId);
  if (!client) {
    return { rerender: renderConsent({ ...view, error: 'Unknown client. Start again from the application you are connecting.', mailbox }) };
  }

  // Grant eviction. A completed consent is the user asserting who may read
  // this mailbox NOW, so every token previously issued for it dies here --
  // across all clients, not just this one. Before this, a victim who
  // removed and re-added the connector left an attacker's 30-day
  // self-rotating token working, and the only real kill switch was deleting
  // the app password in mailcow (still documented in deploy/README.md as
  // the out-of-band one, since it also stops a stolen credential).
  deps.tokens.revokeAllBySubject(mailbox);

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
  res?.clearCookie?.(CONSENT_COOKIE, { path: COOKIE_OPTIONS.path });

  // The redirect target comes ONLY from the pending row saved at
  // authorization time -- never from the consent POST body -- so a
  // malicious body field can't turn this into an open redirect / token
  // theft path.
  const redirect = new URL(pending.redirectUri);
  redirect.searchParams.set('code', code);
  if (pending.state) redirect.searchParams.set('state', pending.state);
  return { redirectTo: redirect.href };
}
