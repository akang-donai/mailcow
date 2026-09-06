import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../../src/remote/db.ts';

test('openDb creates the five tables', () => {
  const db = openDb(':memory:');
  const names = db.prepare("select name from sqlite_master where type='table' order by name")
    .all().map((r: any) => r.name);
  for (const t of ['authorization_codes', 'credentials', 'oauth_clients', 'pending_authorizations', 'tokens']) {
    assert.ok(names.includes(t), `missing table ${t}`);
  }
});

test('oauth_clients round-trips a row', () => {
  const db = openDb(':memory:');
  db.prepare('insert into oauth_clients(client_id,client_name,redirect_uris,grant_types,scope,created_at) values (?,?,?,?,?,?)')
    .run('c1', 'Claude', JSON.stringify(['https://x/cb']), 'authorization_code refresh_token', 'mail', 1000);
  const row: any = db.prepare('select * from oauth_clients where client_id=?').get('c1');
  assert.equal(row.client_name, 'Claude');
  assert.deepEqual(JSON.parse(row.redirect_uris), ['https://x/cb']);
});

test('credentials keyed by subject enforces one row per subject', () => {
  const db = openDb(':memory:');
  const ins = db.prepare('insert into credentials(subject,host,port,ciphertext,nonce,verified_at) values (?,?,?,?,?,?)');
  ins.run('harry@x', 'usagi', 993, 'ct', 'n', 1);
  assert.throws(() => ins.run('harry@x', 'usagi', 993, 'ct2', 'n2', 2));
});

test('tokens table stores by hash and allows revoke marking', () => {
  const db = openDb(':memory:');
  db.prepare('insert into tokens(token_hash,kind,client_id,subject,scope,expires_at) values (?,?,?,?,?,?)')
    .run('h1', 'access', 'c1', 'harry@x', 'mail', 9999);
  assert.equal(db.prepare('update tokens set revoked_at=? where token_hash=?').run(5, 'h1').changes, 1);
  assert.equal(db.prepare('update tokens set consumed_at=? where token_hash=?').run(6, 'h1').changes, 1);
});
