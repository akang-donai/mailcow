// test/remote/provider.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';
import { InvalidTokenError, InvalidScopeError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const TTLS = { code: 60, access: 3600, refresh: 2592000 };

function makeProvider() {
  const db = openDb(':memory:');
  const clientsStore = new SqliteClientsStore(db);
  const codes = new CodeStore(db);
  const tokens = new TokenStore(db);
  const provider = new MailcowOAuthProvider({ clientsStore, codes, tokens, ttls: TTLS });
  return { db, provider, clientsStore, codes, tokens };
}

const client = { client_id: 'c1', redirect_uris: ['https://claude/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any;

test('exchanging a consent-issued code returns access and refresh tokens bound to the subject', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({
    client, subject: 'harry@x',
    params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] },
  });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  assert.ok(tokens.access_token);
  assert.ok(tokens.refresh_token);
  const info = await provider.verifyAccessToken(tokens.access_token);
  assert.equal(info.extra?.subject, 'harry@x');
  assert.equal(info.clientId, 'c1');
});

test('an auth code cannot be exchanged twice', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  await provider.exchangeAuthorizationCode(client, code);
  await assert.rejects(() => provider.exchangeAuthorizationCode(client, code));
});

test('challengeForAuthorizationCode returns the stored PKCE challenge', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'the-challenge', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  assert.equal(await provider.challengeForAuthorizationCode(client, code), 'the-challenge');
});

test('refresh rotation issues a new pair and consumes the old refresh token', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const first = await provider.exchangeAuthorizationCode(client, code);
  const rotated = await provider.exchangeRefreshToken(client, first.refresh_token!, ['mail']);
  assert.ok(rotated.refresh_token && rotated.refresh_token !== first.refresh_token);
  // old refresh now rejected
  await assert.rejects(() => provider.exchangeRefreshToken(client, first.refresh_token!, ['mail']));
});

test('reusing an already-rotated refresh token revokes the whole chain', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const first = await provider.exchangeAuthorizationCode(client, code);
  const second = await provider.exchangeRefreshToken(client, first.refresh_token!, ['mail']);
  // attacker replays the first (already consumed) refresh token
  await assert.rejects(() => provider.exchangeRefreshToken(client, first.refresh_token!, ['mail']));
  // the legitimately-rotated token is now also dead
  await assert.rejects(() => provider.exchangeRefreshToken(client, second.refresh_token!, ['mail']));
});

test('verifyAccessToken rejects an unknown token', async () => {
  const { provider } = makeProvider();
  await assert.rejects(() => provider.verifyAccessToken('nope'));
});

test('authorize throws when no handler is configured', async () => {
  const { provider } = makeProvider();
  const fakeRes = { redirect: () => {} } as any;
  await assert.rejects(() => provider.authorize(client, { codeChallenge: 'c', redirectUri: 'https://claude/cb' } as any, fakeRes));
});

test('authorize calls the configured handler instead of throwing', async () => {
  const { provider } = makeProvider();
  const calls: unknown[] = [];
  const fakeRes = { redirect: (url: string) => { calls.push(url); } } as any;
  provider.setOnAuthorize((c, params, res) => {
    res.redirect(`https://example/consent?client=${c.client_id}&cc=${params.codeChallenge}`);
  });
  await provider.authorize(client, { codeChallenge: 'chal', redirectUri: 'https://claude/cb' } as any, fakeRes);
  assert.deepEqual(calls, ['https://example/consent?client=c1&cc=chal']);
});

test('authorize awaits an async handler before returning', async () => {
  const { provider } = makeProvider();
  let resolved = false;
  provider.setOnAuthorize(async () => {
    await new Promise((r) => setTimeout(r, 5));
    resolved = true;
  });
  await provider.authorize(client, { codeChallenge: 'chal', redirectUri: 'https://claude/cb' } as any, {} as any);
  assert.equal(resolved, true);
});

// ---- Critical 1: token kind must be enforced ----

test('an access token cannot be redeemed at the refresh-token grant', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  await assert.rejects(() => provider.exchangeRefreshToken(client, tokens.access_token, ['mail']));
});

test('a refresh token cannot be used as a bearer access token', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  await assert.rejects(() => provider.verifyAccessToken(tokens.refresh_token!));
});

// ---- Critical 2: verifyAccessToken must throw InvalidTokenError (not InvalidGrantError) ----

test('verifyAccessToken throws InvalidTokenError for an unknown token, so bearerAuth issues a 401 challenge', async () => {
  const { provider } = makeProvider();
  await assert.rejects(() => provider.verifyAccessToken('nope'), (err: unknown) => {
    assert.ok(err instanceof InvalidTokenError, `expected InvalidTokenError, got ${(err as Error)?.constructor?.name}`);
    return true;
  });
});

// ---- Important 3: refresh must not be able to widen scope ----

test('refresh requesting a scope that was never granted is rejected', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  await assert.rejects(
    () => provider.exchangeRefreshToken(client, tokens.refresh_token!, ['mail', 'admin', 'root']),
    (err: unknown) => { assert.ok(err instanceof InvalidScopeError); return true; },
  );
});

test('refresh with no requested scopes preserves the originally granted scope', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  const rotated = await provider.exchangeRefreshToken(client, tokens.refresh_token!);
  assert.equal(rotated.scope, 'mail');
});

// ---- Important 4: redirect_uri must be bound at code exchange ----

test('exchanging a code with a mismatched redirect_uri is rejected', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  await assert.rejects(() => provider.exchangeAuthorizationCode(client, code, undefined, 'https://evil/cb'));
});

test('exchanging a code with the matching redirect_uri still succeeds', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, 'https://claude/cb');
  assert.ok(tokens.access_token);
});

// ---- Important 6: revoking a refresh token must revoke the whole grant (RFC 7009 2.1) ----

test('revoking a refresh token also invalidates its sibling access token', async () => {
  const { provider, clientsStore } = makeProvider();
  await clientsStore.registerClient(client);
  const code = provider.completeAuthorization({ client, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://claude/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(client, code);
  await provider.revokeToken!(client, { token: tokens.refresh_token! });
  await assert.rejects(() => provider.verifyAccessToken(tokens.access_token));
  await assert.rejects(() => provider.exchangeRefreshToken(client, tokens.refresh_token!, ['mail']));
});

// ---- Important 7 + client-binding test gap: a live token presented by the wrong
// client is stronger evidence of theft than a spent one, and kills the real
// owner's session too. This also covers the mutation-tested gap: deleting the
// client check in exchangeRefreshToken must make this test fail. ----

test('a client mismatch on a live refresh token revokes the chain, killing the legitimate client too', async () => {
  const { provider, clientsStore } = makeProvider();
  const clientA = { client_id: 'A', redirect_uris: ['https://a/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any;
  const clientB = { client_id: 'B', redirect_uris: ['https://b/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any;
  await clientsStore.registerClient(clientA);
  await clientsStore.registerClient(clientB);
  const code = provider.completeAuthorization({ client: clientA, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://a/cb', scopes: ['mail'] } });
  const tokens = await provider.exchangeAuthorizationCode(clientA, code);
  // attacker holds client B's credentials but presents A's live refresh token
  await assert.rejects(() => provider.exchangeRefreshToken(clientB, tokens.refresh_token!, ['mail']));
  // the legitimate client A can no longer use it either -- the whole chain died
  await assert.rejects(() => provider.exchangeRefreshToken(clientA, tokens.refresh_token!, ['mail']));
});

// ---- Test gap: client binding on the authorization-code exchange was unguarded by any test ----

test('an authorization code issued to one client cannot be redeemed by another', async () => {
  const { provider, clientsStore } = makeProvider();
  const clientA = { client_id: 'A', redirect_uris: ['https://a/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any;
  const clientB = { client_id: 'B', redirect_uris: ['https://b/cb'], grant_types: ['authorization_code', 'refresh_token'] } as any;
  await clientsStore.registerClient(clientA);
  await clientsStore.registerClient(clientB);
  const code = provider.completeAuthorization({ client: clientA, subject: 'harry@x', params: { codeChallenge: 'chal', redirectUri: 'https://a/cb', scopes: ['mail'] } });
  await assert.rejects(() => provider.exchangeAuthorizationCode(clientB, code));
});
