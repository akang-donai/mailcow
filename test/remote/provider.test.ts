// test/remote/provider.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';

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
