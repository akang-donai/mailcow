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
