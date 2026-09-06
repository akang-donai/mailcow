// test/remote/consent.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore, PendingStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';
import { renderConsent, beginConsent, handleConsent, consentView, redirectDestination, readConsentCookie, CONSENT_COOKIE } from '../../src/remote/consent.ts';

function fixture(verifyResult: boolean, clientOverrides: Record<string, unknown> = {}, smtpProbe: any = async () => 'rejected') {
  const db = openDb(':memory:');
  const clientsStore = new SqliteClientsStore(db);
  clientsStore.registerClient({ client_id: 'c1', client_name: 'Claude', redirect_uris: ['https://claude/cb'], grant_types: ['authorization_code', 'refresh_token'], ...clientOverrides } as any);
  const tokens = new TokenStore(db);
  const provider = new MailcowOAuthProvider({ clientsStore, codes: new CodeStore(db), tokens, ttls: { code: 60, access: 3600, refresh: 2592000 } });
  const credentials = new CredentialStore(db, randomBytes(32));
  const pending = new PendingStore(db);
  const verify = async () => verifyResult;
  return {
    db, clientsStore, provider, credentials, pending, tokens,
    deps: { pending, credentials, provider, clientsStore, tokens, verify, imapHost: 'usagi', imapPort: 993, smtpProbe, smtpHost: 'usagi', smtpPort: 465 },
  };
}

// A response stub that records the browser-binding cookie beginConsent sets.
// A real browser would send it straight back on the consent POST; every test
// that expects a POST to succeed threads it through the same way.
function cookieJar() {
  let value = '';
  return {
    res: {
      cookie(name: string, v: string) { if (name === CONSENT_COOKIE) value = v; },
      clearCookie() {},
    },
    get token() { return value; },
  };
}

const PARAMS = { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] };

// Start a consent flow the way /authorize does, returning both halves of
// the binding: the handle (which travels in the URL) and the cookie value.
function begin(deps: any, params: Record<string, unknown> = {}) {
  const jar = cookieJar();
  const url = beginConsent(deps, jar.res, { ...PARAMS, ...params } as any);
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  return { url, handle, browserToken: jar.token };
}

// Everything a renderConsent call needs when the test is only exercising
// escaping or field presence, not identification.
const VIEW = { clientName: 'Claude', redirectOrigin: 'https://claude' };

test('renderConsent produces a form with mailbox and app_password fields and the handle', () => {
  const html = renderConsent({ ...VIEW, handle: 'h1' });
  assert.match(html, /name="mailbox"/);
  assert.match(html, /name="app_password"/);
  assert.match(html, /value="h1"/);
  assert.doesNotMatch(html, /onclick=/i); // CSP-safe, no inline handlers
});

test('beginConsent stores a pending row and returns the consent URL', () => {
  const { deps, pending } = fixture(true);
  const { url, handle } = begin(deps);
  assert.match(url, /^\/consent\?handle=/);
  assert.ok(pending.get(handle));
});

test('handleConsent with a valid app password stores credential and redirects with code+state', async () => {
  const { deps, credentials } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);
  assert.ok('redirectTo' in res);
  const redirect = new URL((res as any).redirectTo);
  assert.equal(redirect.origin + redirect.pathname, 'https://claude/cb');
  assert.ok(redirect.searchParams.get('code'));
  assert.equal(redirect.searchParams.get('state'), 'st');
  assert.ok(credentials.get('harry@x'), 'credential stored');
});

test('handleConsent with a bad app password rerenders with an error and stores nothing', async () => {
  const { deps, credentials } = fixture(false);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'bad-pw' }, browserToken);
  assert.ok('rerender' in res);
  assert.match((res as any).rerender, /could not sign in|invalid/i);
  assert.equal(credentials.get('harry@x'), null);
});

test('handleConsent rejects an unknown or expired handle', async () => {
  const { deps } = fixture(true);
  const res = await handleConsent(deps, { handle: 'nope', mailbox: 'harry@x', app_password: 'good-pw' }, 'no-such-cookie');
  assert.ok('rerender' in res);
});

test('handleConsent escapes the mailbox value when rerendering (no HTML injection)', async () => {
  const { deps } = fixture(false);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: '<script>x</script>', app_password: 'bad' }, browserToken);
  assert.ok('rerender' in res);
  assert.doesNotMatch((res as any).rerender, /<script>x<\/script>/);
});

// --- Additional security-hardening tests beyond the brief's baseline ---

test('renderConsent escapes a handle containing a quote to prevent attribute breakout', () => {
  const evil = 'h1" onmouseover="alert(1)';
  const html = renderConsent({ ...VIEW, handle: evil });
  // The raw payload must never appear verbatim inside the value="" attribute.
  assert.doesNotMatch(html, /value="h1" onmouseover="alert\(1\)"/);
  // It must appear properly escaped instead.
  assert.match(html, /value="h1&quot; onmouseover=&quot;alert\(1\)"/);
});

test('handleConsent never echoes the submitted app password anywhere in the rerendered HTML', async () => {
  const { deps } = fixture(false);
  const { handle, browserToken } = begin(deps);
  const secret = 'sUpEr-Secret-App-Password-42';
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: secret }, browserToken);
  assert.ok('rerender' in res);
  assert.doesNotMatch((res as any).rerender, new RegExp(secret));
  // and the app_password input must render with no value attribute at all
  assert.doesNotMatch((res as any).rerender, /name="app_password"[^>]*value=/);
});

test('a used handle is single-use: replaying it after a successful consent fails', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const first = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);
  assert.ok('redirectTo' in first);
  const replay = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);
  assert.ok('rerender' in replay, 'replaying a spent handle must not mint a second code');
});

test('handleConsent redirects only to the redirect_uri stored with the pending row, never one supplied in the POST body', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, {
    handle,
    mailbox: 'harry@x',
    app_password: 'good-pw',
    // @ts-expect-error -- attacker-supplied field the type does not declare
    redirect_uri: 'https://evil.example/steal',
  }, browserToken);
  assert.ok('redirectTo' in res);
  const redirect = new URL((res as any).redirectTo);
  assert.equal(redirect.origin, 'https://claude');
});

// --- Runtime type validation of body fields ---
//
// The `body` parameter's TypeScript type is a compile-time shape only: Node
// strips types without checking them at runtime, and a real HTTP request is
// not obligated to match it. Express's urlencoded body parser turns a
// DUPLICATED form field (e.g. two `handle=` fields) into an array, and a
// hand-crafted request can hand any of these fields a number, null, or an
// object. None of that should ever reach `hashToken`, `.trim()`, or the
// IMAP verifier uncaught -- it must be treated exactly like a missing field
// and take the existing `{ rerender }` path. These tests bypass the
// function's declared parameter type with `as any` at the call site (the
// way a real deserialized request body would arrive), rather than loosening
// the function's declared type -- the declared type remains the correct
// contract for callers who honour it.

test('handleConsent returns rerender, not a throw, when handle is submitted as an array (duplicated form field)', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle: [handle, handle] as any, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, when mailbox is submitted as an array (duplicated form field)', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: ['harry@x', 'evil@x'] as any, app_password: 'good-pw' }, browserToken);
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, when app_password is submitted as an array (duplicated form field)', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: ['good-pw', 'evil-pw'] as any }, browserToken);
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, for non-string body fields of other types (number, null, object)', async () => {
  const { deps } = fixture(true);
  const { handle, browserToken } = begin(deps);

  const badBodies: any[] = [
    { handle: 12345, mailbox: 'harry@x', app_password: 'good-pw' },
    { handle: null, mailbox: 'harry@x', app_password: 'good-pw' },
    { handle: { toString: () => handle }, mailbox: 'harry@x', app_password: 'good-pw' },
    { handle, mailbox: 42, app_password: 'good-pw' },
    { handle, mailbox: null, app_password: 'good-pw' },
    { handle, mailbox: { evil: true }, app_password: 'good-pw' },
    { handle, mailbox: 'harry@x', app_password: 42 },
    { handle, mailbox: 'harry@x', app_password: null },
    { handle, mailbox: 'harry@x', app_password: { evil: true } },
  ];
  for (const body of badBodies) {
    const res = await handleConsent(deps, body, browserToken);
    assert.ok('rerender' in res, `expected rerender for body ${JSON.stringify(body)}`);
  }
});

// ---------------------------------------------------------------------------
// Identification. Dynamic client registration is open by design, so the page
// must name the client that actually asked and, prominently, where the
// browser will be sent -- and must NOT assert a vendor name of its own. The
// old page said "This grants Claude read-only access to your mail" while
// naming neither, so a rogue client registered with
// redirect_uri=https://evil.example/cb produced a page, on the genuine host
// with the genuine certificate, telling the victim they were connecting
// Claude.
// ---------------------------------------------------------------------------

test('the consent page names the requesting client and the redirect origin, and claims no vendor of its own', () => {
  const { deps } = fixture(true, { client_id: 'c1', client_name: 'Definitely Legitimate Mail Reader', redirect_uris: ['https://evil.example/cb'] });
  const { handle } = begin(deps, { redirectUri: 'https://evil.example/cb' });

  const html = renderConsent(consentView(deps, handle));

  assert.match(html, /Definitely Legitimate Mail Reader/, 'the page must name the client that actually asked');
  assert.match(html, /https:\/\/evil\.example/, 'the page must show where the browser will be sent');
  assert.doesNotMatch(html, /Claude/, 'the page must not assert a vendor name the request never mentioned');
});

test('the redirect origin is rendered without the attacker-chosen path, so a decorative path cannot dress it up', () => {
  const { deps } = fixture(true, { client_id: 'c1', client_name: 'x', redirect_uris: ['https://evil.example/claude.ai/connectors/authorise'] });
  const { handle } = begin(deps, { redirectUri: 'https://evil.example/claude.ai/connectors/authorise' });

  const html = renderConsent(consentView(deps, handle));

  assert.match(html, /https:\/\/evil\.example/);
  assert.doesNotMatch(html, /claude\.ai/, 'only the origin is shown; a path chosen to look reassuring is not');
});

test('a client name and redirect URI carrying HTML are escaped, not rendered', () => {
  const { deps } = fixture(true, { client_id: 'c1', client_name: '<img src=x onerror=alert(1)>', redirect_uris: ['https://evil.example/cb'] });
  const { handle } = begin(deps, { redirectUri: 'https://evil.example/cb' });

  const html = renderConsent(consentView(deps, handle));

  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('an unregistered or nameless client is labelled as unidentified rather than left blank', () => {
  const { deps } = fixture(true, { client_id: 'c1', client_name: undefined, redirect_uris: ['https://claude/cb'] });
  const { handle } = begin(deps);
  const view = consentView(deps, handle);
  assert.match(view.clientName, /unidentified/i);
  assert.doesNotMatch(renderConsent(view), /undefined/);
});

test('redirectDestination shows the origin for an http(s) URI and the whole URI for an opaque one', () => {
  assert.equal(redirectDestination('https://evil.example/cb?x=1'), 'https://evil.example');
  // Custom app schemes have a "null" origin, which would tell a reader
  // nothing at all -- show the URI itself instead.
  assert.equal(redirectDestination('com.example.app://cb'), 'com.example.app://cb');
  assert.equal(redirectDestination('not a url'), 'not a url');
});

// ---------------------------------------------------------------------------
// Browser binding. The pending handle is a bearer value that travels in a
// URL, so on its own it lets an attacker run /authorize in their browser and
// hand the consent link to a victim. The cookie set at /authorize time is
// the second half.
// ---------------------------------------------------------------------------

test('a consent POST with no cookie at all is rejected and issues no code', async () => {
  const { deps, credentials } = fixture(true);
  const { handle } = begin(deps);

  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, '');

  assert.ok('rerender' in res, 'a consent POST without the binding cookie must not mint a code');
  assert.match((res as any).rerender, /not started in this browser/i);
  assert.equal(credentials.get('harry@x'), null, 'nothing may be stored either');
});

test("a consent POST carrying another flow's cookie is rejected", async () => {
  const { deps } = fixture(true);
  const victim = begin(deps);
  const attacker = begin(deps);

  // The attacker's browser holds the attacker's cookie; presenting it
  // against the victim's handle must not work.
  const res = await handleConsent(deps, { handle: victim.handle, mailbox: 'harry@x', app_password: 'good-pw' }, attacker.browserToken);

  assert.ok('rerender' in res);
});

test('the cross-browser handoff attack fails: an attacker-started /authorize cannot be completed by a victim', async () => {
  // The attacker registers their own client, runs /authorize themselves --
  // so the pending row's redirect_uri is theirs -- and sends the victim the
  // /consent link. The victim's browser has no cookie for that flow.
  const { deps, credentials } = fixture(true, { client_id: 'c1', client_name: 'Mail Helper', redirect_uris: ['https://evil.example/cb'] });
  const attacker = begin(deps, { redirectUri: 'https://evil.example/cb' });

  const victimResult = await handleConsent(deps, { handle: attacker.handle, mailbox: 'victim@x', app_password: 'good-pw' }, '');

  assert.ok('rerender' in victimResult, 'the victim must not be redirected to the attacker with a code');
  assert.equal(credentials.get('victim@x'), null);
});

test('a pending row written before the binding existed fails closed rather than open', async () => {
  const { deps, db } = fixture(true);
  const { handle } = begin(deps);
  // Simulate a legacy row: the migration adds the column nullable, so an
  // in-flight authorization from before the upgrade has no hash stored.
  db.prepare('update pending_authorizations set browser_token_hash=null').run();

  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, 'anything');

  assert.ok('rerender' in res);
});

test('beginConsent sets an HttpOnly, Secure, SameSite=Lax cookie scoped to /consent', () => {
  const { deps } = fixture(true);
  const recorded: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
  beginConsent(deps, { cookie: (name, value, options) => recorded.push({ name, value, options }) } as any, PARAMS as any);

  assert.equal(recorded.length, 1);
  const { name, value, options } = recorded[0]!;
  assert.equal(name, CONSENT_COOKIE);
  assert.ok(value.length >= 32, 'the binding value must be a real secret, not a marker');
  assert.equal(options.httpOnly, true);
  assert.equal(options.secure, true);
  assert.equal(options.sameSite, 'lax');
  assert.equal(options.path, '/consent');
});

test('the binding value is stored hashed, never in the clear', () => {
  const { deps, db } = fixture(true);
  const { browserToken } = begin(deps);
  const row: any = db.prepare('select browser_token_hash from pending_authorizations').get();
  assert.ok(row.browser_token_hash);
  assert.notEqual(row.browser_token_hash, browserToken);
});

test('readConsentCookie finds the value among other cookies and ignores everything else', () => {
  assert.equal(readConsentCookie(`a=1; ${CONSENT_COOKIE}=abc123; b=2`), 'abc123');
  assert.equal(readConsentCookie('a=1; b=2'), '');
  assert.equal(readConsentCookie(undefined), '');
  // A cookie whose NAME merely contains ours must not be accepted.
  assert.equal(readConsentCookie(`not_${CONSENT_COOKIE}=abc123`), '');
});

// ---------------------------------------------------------------------------
// Grant eviction. Before this, a victim who removed and re-added the
// connector left an attacker's 30-day self-rotating token working; the only
// kill switch was deleting the app password in mailcow.
// ---------------------------------------------------------------------------

test('completing a new consent revokes every token previously issued for that mailbox', async () => {
  const { deps, tokens } = fixture(true);
  const stolen = tokens.issue({ kind: 'access', clientId: 'attacker', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });
  const stolenRefresh = tokens.issue({ kind: 'refresh', clientId: 'attacker', subject: 'harry@x', scope: 'mail', ttlSec: 2592000 });
  assert.ok(tokens.verify(stolen, 'access'), 'precondition: the old token works');

  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);
  assert.ok('redirectTo' in res);

  assert.equal(tokens.verify(stolen, 'access'), null, 're-consenting must kill the previously issued access token');
  assert.equal(tokens.verify(stolenRefresh, 'refresh'), null, '...and its refresh token, so it cannot rotate itself back');
});

test('re-consenting for one mailbox does not disturb another mailbox\'s tokens', async () => {
  const { deps, tokens } = fixture(true);
  const other = tokens.issue({ kind: 'access', clientId: 'c1', subject: 'dea@x', scope: 'mail', ttlSec: 3600 });

  const { handle, browserToken } = begin(deps);
  await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' }, browserToken);

  assert.ok(tokens.verify(other, 'access'), 'eviction is scoped to the subject that re-consented');
});

test('a FAILED consent does not revoke anything', async () => {
  const { deps, tokens } = fixture(false); // IMAP refuses the credential
  const existing = tokens.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });

  const { handle, browserToken } = begin(deps);
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'wrong-pw' }, browserToken);

  assert.ok('rerender' in res);
  assert.ok(tokens.verify(existing, 'access'), 'a wrong password must not be a way to log a user out');
});

// ---------------------------------------------------------------------------
// Scope verification. The design puts sending out of scope because the
// credentials are "scoped to imap_access, verified by
// scripts/check-no-smtp.ts" -- but that script reads Step A's accounts file
// and cannot see these encrypted per-subject rows. Nothing checked scope at
// consent time, so pasting a full mailbox password enrolled you and left a
// send-capable credential in the database: the outcome the design named as
// the worst one under breach.
// ---------------------------------------------------------------------------

test('a credential that authenticates to SMTP is refused, and nothing is stored', async () => {
  const { deps, credentials } = fixture(true, {}, async () => 'accepted');
  const { handle, browserToken } = begin(deps);

  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'full-mailbox-pw' }, browserToken);

  assert.ok('rerender' in res, 'a send-capable credential must not be enrolled');
  assert.match((res as any).rerender, /can also SEND mail/i);
  assert.match((res as any).rerender, /imap_access/, 'the user must be told what to do instead');
  assert.equal(credentials.get('harry@x'), null, 'a send-capable credential must never reach the database');
});

test('a credential SMTP refuses is accepted -- that is a correctly scoped app password', async () => {
  const { deps, credentials } = fixture(true, {}, async () => 'rejected');
  const { handle, browserToken } = begin(deps);

  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'imap-only-pw' }, browserToken);

  assert.ok('redirectTo' in res);
  assert.ok(credentials.get('harry@x'));
});

test('an unreachable SMTP host does not block enrolment, but is logged', async () => {
  // A mailcow with SMTP disabled, firewalled, or on a STARTTLS-only port
  // must not make every enrolment on the domain impossible. Inconclusive is
  // permissive by design -- and noisy, so it is not silently permissive.
  const { deps, credentials } = fixture(true, {}, async () => 'unknown');
  const { handle, browserToken } = begin(deps);

  const warnings: unknown[][] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args); };
  try {
    const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'pw' }, browserToken);
    assert.ok('redirectTo' in res, 'an unreachable SMTP endpoint must not block enrolment');
    assert.ok(credentials.get('harry@x'));
  } finally {
    console.warn = original;
  }
  assert.ok(warnings.length > 0, 'an unverified scope must be logged, not silently accepted');
  assert.match(String(warnings[0]), /inconclusive|UNVERIFIED/i);
});

test('a probe that throws is inconclusive, not a 500 and not a pass-as-scoped', async () => {
  const { deps } = fixture(true, {}, async () => { throw new Error('ECONNREFUSED'); });
  const { handle, browserToken } = begin(deps);
  const original = console.warn;
  console.warn = () => {};
  try {
    const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'pw' }, browserToken);
    assert.ok('redirectTo' in res);
  } finally {
    console.warn = original;
  }
});

test('the scope probe is only consulted after IMAP has proven the credential', async () => {
  // An SMTP refusal proves nothing about a credential IMAP also refused --
  // a typo is refused everywhere and would look perfectly scoped. So a bad
  // password must never even reach the probe.
  let probed = 0;
  const { deps } = fixture(false, {}, async () => { probed += 1; return 'rejected' as const; });
  const { handle, browserToken } = begin(deps);

  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'wrong' }, browserToken);

  assert.ok('rerender' in res);
  assert.equal(probed, 0, 'the SMTP probe must not run for a credential IMAP already refused');
});

test('a refused send-capable credential does not revoke the user\'s existing tokens', async () => {
  const { deps, tokens } = fixture(true, {}, async () => 'accepted');
  const existing = tokens.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });
  const { handle, browserToken } = begin(deps);

  await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'full-pw' }, browserToken);

  assert.ok(tokens.verify(existing, 'access'), 'a rejected enrolment must not log the user out');
});

test('the probe receives the configured SMTP host and port and the submitted credential', async () => {
  const calls: Array<[string, number, string, string]> = [];
  const { deps } = fixture(true, {}, async (...args: [string, number, string, string]) => { calls.push(args); return 'rejected' as const; });
  const { handle, browserToken } = begin(deps);

  await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'pw-123' }, browserToken);

  assert.deepEqual(calls, [['usagi', 465, 'harry@x', 'pw-123']]);
});
