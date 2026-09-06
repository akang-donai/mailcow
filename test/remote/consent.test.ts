// test/remote/consent.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore, PendingStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';
import { renderConsent, beginConsent, handleConsent } from '../../src/remote/consent.ts';

function fixture(verifyResult: boolean) {
  const db = openDb(':memory:');
  const clientsStore = new SqliteClientsStore(db);
  clientsStore.registerClient({ client_id: 'c1', redirect_uris: ['https://claude/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any);
  const provider = new MailcowOAuthProvider({ clientsStore, codes: new CodeStore(db), tokens: new TokenStore(db), ttls: { code: 60, access: 3600, refresh: 2592000 } });
  const credentials = new CredentialStore(db, randomBytes(32));
  const pending = new PendingStore(db);
  const verify = async () => verifyResult;
  return { db, clientsStore, provider, credentials, pending, deps: { pending, credentials, provider, clientsStore, verify, imapHost: 'usagi', imapPort: 993 } };
}

test('renderConsent produces a form with mailbox and app_password fields and the handle', () => {
  const html = renderConsent('h1');
  assert.match(html, /name="mailbox"/);
  assert.match(html, /name="app_password"/);
  assert.match(html, /value="h1"/);
  assert.doesNotMatch(html, /onclick=/i); // CSP-safe, no inline handlers
});

test('beginConsent stores a pending row and returns the consent URL', () => {
  const { deps, pending } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  assert.match(url, /^\/consent\?handle=/);
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  assert.ok(pending.get(handle));
});

test('handleConsent with a valid app password stores credential and redirects with code+state', async () => {
  const { deps, credentials } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' });
  assert.ok('redirectTo' in res);
  const redirect = new URL((res as any).redirectTo);
  assert.equal(redirect.origin + redirect.pathname, 'https://claude/cb');
  assert.ok(redirect.searchParams.get('code'));
  assert.equal(redirect.searchParams.get('state'), 'st');
  assert.ok(credentials.get('harry@x'), 'credential stored');
});

test('handleConsent with a bad app password rerenders with an error and stores nothing', async () => {
  const { deps, credentials } = fixture(false);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'bad-pw' });
  assert.ok('rerender' in res);
  assert.match((res as any).rerender, /could not sign in|invalid/i);
  assert.equal(credentials.get('harry@x'), null);
});

test('handleConsent rejects an unknown or expired handle', async () => {
  const { deps } = fixture(true);
  const res = await handleConsent(deps, { handle: 'nope', mailbox: 'harry@x', app_password: 'good-pw' });
  assert.ok('rerender' in res);
});

test('handleConsent escapes the mailbox value when rerendering (no HTML injection)', async () => {
  const { deps } = fixture(false);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle, mailbox: '<script>x</script>', app_password: 'bad' });
  assert.ok('rerender' in res);
  assert.doesNotMatch((res as any).rerender, /<script>x<\/script>/);
});

// --- Additional security-hardening tests beyond the brief's baseline ---

test('renderConsent escapes a handle containing a quote to prevent attribute breakout', () => {
  const evil = 'h1" onmouseover="alert(1)';
  const html = renderConsent(evil);
  // The raw payload must never appear verbatim inside the value="" attribute.
  assert.doesNotMatch(html, /value="h1" onmouseover="alert\(1\)"/);
  // It must appear properly escaped instead.
  assert.match(html, /value="h1&quot; onmouseover=&quot;alert\(1\)"/);
});

test('handleConsent never echoes the submitted app password anywhere in the rerendered HTML', async () => {
  const { deps } = fixture(false);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const secret = 'sUpEr-Secret-App-Password-42';
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: secret });
  assert.ok('rerender' in res);
  assert.doesNotMatch((res as any).rerender, new RegExp(secret));
  // and the app_password input must render with no value attribute at all
  assert.doesNotMatch((res as any).rerender, /name="app_password"[^>]*value=/);
});

test('a used handle is single-use: replaying it after a successful consent fails', async () => {
  const { deps } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const first = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' });
  assert.ok('redirectTo' in first);
  const replay = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: 'good-pw' });
  assert.ok('rerender' in replay, 'replaying a spent handle must not mint a second code');
});

test('handleConsent redirects only to the redirect_uri stored with the pending row, never one supplied in the POST body', async () => {
  const { deps } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, {
    handle,
    mailbox: 'harry@x',
    app_password: 'good-pw',
    // @ts-expect-error -- attacker-supplied field the type does not declare
    redirect_uri: 'https://evil.example/steal',
  });
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
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle: [handle, handle] as any, mailbox: 'harry@x', app_password: 'good-pw' });
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, when mailbox is submitted as an array (duplicated form field)', async () => {
  const { deps } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle, mailbox: ['harry@x', 'evil@x'] as any, app_password: 'good-pw' });
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, when app_password is submitted as an array (duplicated form field)', async () => {
  const { deps } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;
  const res = await handleConsent(deps, { handle, mailbox: 'harry@x', app_password: ['good-pw', 'evil-pw'] as any });
  assert.ok('rerender' in res);
});

test('handleConsent returns rerender, not a throw, for non-string body fields of other types (number, null, object)', async () => {
  const { deps } = fixture(true);
  const url = beginConsent(deps, { clientId: 'c1', redirectUri: 'https://claude/cb', codeChallenge: 'chal', state: 'st', resource: undefined, scopes: ['mail'] });
  const handle = new URL('http://x' + url).searchParams.get('handle')!;

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
    const res = await handleConsent(deps, body);
    assert.ok('rerender' in res, `expected rerender for body ${JSON.stringify(body)}`);
  }
});
