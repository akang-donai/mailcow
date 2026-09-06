// test/remote/store.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore } from '../../src/remote/store.ts';

const key = randomBytes(32);
const now = () => Math.floor(Date.now() / 1000);

test('clients store persists and retrieves a registered client', async () => {
  const store = new SqliteClientsStore(openDb(':memory:'));
  const reg = await store.registerClient({
    client_id: 'c1', redirect_uris: ['https://x/cb'],
    grant_types: ['authorization_code', 'refresh_token'], client_name: 'Claude',
  } as any);
  assert.equal(reg.client_id, 'c1');
  const got = await store.getClient('c1');
  assert.deepEqual(got?.redirect_uris, ['https://x/cb']);
});

test('code store consumes a code exactly once', () => {
  const cs = new CodeStore(openDb(':memory:'));
  cs.save('code1', { clientId: 'c1', subject: 'harry@x', codeChallenge: 'chal', redirectUri: 'https://x/cb', resource: undefined, ttlSec: 60 });
  const first = cs.consume('code1');
  assert.equal(first?.subject, 'harry@x');
  assert.equal(cs.consume('code1'), null); // replay rejected
});

test('clients store round-trips a confidential client secret and its expiry', async () => {
  const store = new SqliteClientsStore(openDb(':memory:'));
  await store.registerClient({
    client_id: 'c2', redirect_uris: ['https://x/cb'],
    grant_types: ['authorization_code', 'refresh_token'], client_name: 'Confidential App',
    client_secret: 'shh-its-a-secret', client_secret_expires_at: 1234567890,
  } as any);
  const got = await store.getClient('c2');
  assert.equal(got?.client_secret, 'shh-its-a-secret');
  assert.equal(got?.client_secret_expires_at, 1234567890);
});

test('clients store leaves client_secret undefined for a public client', async () => {
  const store = new SqliteClientsStore(openDb(':memory:'));
  await store.registerClient({
    client_id: 'c3', redirect_uris: ['https://x/cb'],
    grant_types: ['authorization_code', 'refresh_token'], client_name: 'Public App',
  } as any);
  const got = await store.getClient('c3');
  assert.equal(got?.client_secret, undefined);
});

test('clients store round-trips client_secret_expires_at as a number', async () => {
  const store = new SqliteClientsStore(openDb(':memory:'));
  await store.registerClient({
    client_id: 'c4', redirect_uris: ['https://x/cb'],
    grant_types: ['authorization_code', 'refresh_token'], client_name: 'Confidential App',
    client_secret: 'another-secret', client_secret_expires_at: 42,
  } as any);
  const got = await store.getClient('c4');
  assert.equal(typeof got?.client_secret_expires_at, 'number');
});

test('code store rejects an expired code', () => {
  const cs = new CodeStore(openDb(':memory:'));
  cs.save('old', { clientId: 'c1', subject: 'harry@x', codeChallenge: 'chal', redirectUri: 'https://x/cb', resource: undefined, ttlSec: -1 });
  assert.equal(cs.consume('old'), null);
});

test('token store issues an opaque token that verifies', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });
  assert.match(tok, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(ts.verify(tok)?.subject, 'harry@x');
});

test('token store returns null for an expired token', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: -1 });
  assert.equal(ts.verify(tok), null);
});

test('token store returns null for an unknown token', () => {
  const ts = new TokenStore(openDb(':memory:'));
  assert.equal(ts.verify('nope'), null);
});

test('refresh reuse detection: consumed token is detectable, chain revocable', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const r1 = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  ts.markConsumed(r1);
  assert.equal(ts.isConsumedOrRevoked(r1), true);
  const r2 = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000, rotatedFrom: r1 });
  ts.revokeChainBySubjectClient('harry@x', 'c1');
  assert.equal(ts.verify(r2), null);
});

test('credential store encrypts at rest and decrypts on get', () => {
  const db = openDb(':memory:');
  const cs = new CredentialStore(db, key);
  cs.put('harry@x', 'usagi', 993, 'app-pw');
  const raw: any = db.prepare('select ciphertext from credentials where subject=?').get('harry@x');
  assert.ok(!raw.ciphertext.includes('app-pw'));
  assert.deepEqual(cs.get('harry@x'), { host: 'usagi', port: 993, appPassword: 'app-pw' });
});

test('credential store returns null once marked invalid', () => {
  const cs = new CredentialStore(openDb(':memory:'), key);
  cs.put('harry@x', 'usagi', 993, 'app-pw');
  cs.markInvalid('harry@x');
  assert.equal(cs.get('harry@x'), null);
});

test('peekChallenge returns the stored challenge without consuming the code', () => {
  const cs = new CodeStore(openDb(':memory:'));
  cs.save('code1', { clientId: 'c1', subject: 'harry@x', codeChallenge: 'the-challenge', redirectUri: 'https://x/cb', resource: undefined, ttlSec: 60 });
  assert.equal(cs.peekChallenge('code1'), 'the-challenge');
  // still consumable afterwards -- peeking must not mark it used
  const consumed = cs.consume('code1');
  assert.equal(consumed?.subject, 'harry@x');
});

test('peekChallenge returns null for an unknown code', () => {
  const cs = new CodeStore(openDb(':memory:'));
  assert.equal(cs.peekChallenge('nope'), null);
});

test('peekChallenge returns null for an expired code', () => {
  const cs = new CodeStore(openDb(':memory:'));
  cs.save('old', { clientId: 'c1', subject: 'harry@x', codeChallenge: 'chal', redirectUri: 'https://x/cb', resource: undefined, ttlSec: -1 });
  assert.equal(cs.peekChallenge('old'), null);
});

test('peekChallenge returns null for an already-consumed code', () => {
  const cs = new CodeStore(openDb(':memory:'));
  cs.save('code1', { clientId: 'c1', subject: 'harry@x', codeChallenge: 'chal', redirectUri: 'https://x/cb', resource: undefined, ttlSec: 60 });
  cs.consume('code1');
  assert.equal(cs.peekChallenge('code1'), null);
});

test('subjectClientOf resolves subject and client for a live token', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  assert.deepEqual(ts.subjectClientOf(tok), { subject: 'harry@x', clientId: 'c1', kind: 'refresh' });
});

test('subjectClientOf still resolves a consumed token (needed for chain revocation)', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  ts.markConsumed(tok);
  assert.deepEqual(ts.subjectClientOf(tok), { subject: 'harry@x', clientId: 'c1', kind: 'refresh' });
});

test('subjectClientOf still resolves a revoked token', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  ts.revoke(tok);
  assert.deepEqual(ts.subjectClientOf(tok), { subject: 'harry@x', clientId: 'c1', kind: 'refresh' });
});

test('subjectClientOf returns null for an unknown token', () => {
  const ts = new TokenStore(openDb(':memory:'));
  assert.equal(ts.subjectClientOf('nope'), null);
});

test('subjectClientOf reports the token kind', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const access = ts.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });
  const refresh = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  assert.equal(ts.subjectClientOf(access)?.kind, 'access');
  assert.equal(ts.subjectClientOf(refresh)?.kind, 'refresh');
});

test('verify with an expectedKind rejects a token of the wrong kind', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const access = ts.issue({ kind: 'access', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 3600 });
  assert.equal(ts.verify(access, 'refresh'), null);
  assert.ok(ts.verify(access, 'access'));
  assert.ok(ts.verify(access)); // no expectedKind: unchanged behaviour
});

test('markConsumed is single-use: the second call loses the race', () => {
  const ts = new TokenStore(openDb(':memory:'));
  const tok = ts.issue({ kind: 'refresh', clientId: 'c1', subject: 'harry@x', scope: 'mail', ttlSec: 1000 });
  assert.equal(ts.markConsumed(tok), true);
  assert.equal(ts.markConsumed(tok), false);
});
