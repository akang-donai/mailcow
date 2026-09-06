import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../../src/remote/db.ts';
import { CredentialStore } from '../../src/remote/store.ts';
import { TenantRegistry, CredentialUnavailableError } from '../../src/remote/tenant-connections.ts';

const key = randomBytes(32);

function fixture(opts: { maxConnections?: number; idleMs?: number } = {}) {
  const creds = new CredentialStore(openDb(':memory:'), key);
  creds.put('harry@x', 'usagi', 993, 'harry-pw');
  creds.put('dea@x', 'usagi', 993, 'dea-pw');
  const dials: Array<{ user: string; pass: string }> = [];
  let clock = 1000;
  const clients = new Map<string, any>();
  const connector = (host: string, port: number, user: string, pass: string) => {
    dials.push({ user, pass });
    const c = { usable: false, connect: async () => { c.usable = true; }, logout: async () => { c.usable = false; }, forceUnusable: () => { c.usable = false; } };
    clients.set(user, c);
    return c;
  };
  const registry = new TenantRegistry({ credentials: creds, connector, clock: () => clock, ...opts });
  return { registry, dials, clients, creds, tick: (ms: number) => { clock += ms; } };
}

test('dials with the decrypted credential for the subject', async () => {
  const { registry, dials } = fixture();
  await registry.get('harry@x');
  assert.deepEqual(dials, [{ user: 'harry@x', pass: 'harry-pw' }]);
});

test('reuses a live connection', async () => {
  const { registry, dials } = fixture();
  await registry.get('harry@x');
  await registry.get('harry@x');
  assert.equal(dials.length, 1);
});

test('reconnects when the connection went unusable', async () => {
  const { registry, dials, clients } = fixture();
  await registry.get('harry@x');
  clients.get('harry@x').forceUnusable();
  await registry.get('harry@x');
  assert.equal(dials.length, 2);
});

test('keeps tenants isolated — each dials with its own credential', async () => {
  const { registry, dials } = fixture();
  await registry.get('harry@x');
  await registry.get('dea@x');
  assert.deepEqual(dials, [{ user: 'harry@x', pass: 'harry-pw' }, { user: 'dea@x', pass: 'dea-pw' }]);
});

test('throws CredentialUnavailableError when no credential is stored', async () => {
  const { registry } = fixture();
  await assert.rejects(() => registry.get('stranger@x'), CredentialUnavailableError);
});

test('evicts a connection idle beyond idleMs and redials on next use', async () => {
  const { registry, dials, tick } = fixture({ idleMs: 5000 });
  await registry.get('harry@x');
  tick(6000);
  await registry.get('harry@x');
  assert.equal(dials.length, 2);
});

test('evicts least-recently-used past maxConnections', async () => {
  const { registry, dials, tick, creds } = fixture({ maxConnections: 1 });
  await registry.get('harry@x');
  tick(1);
  await registry.get('dea@x');   // evicts harry
  await registry.get('harry@x'); // redial
  assert.equal(dials.filter((d) => d.user === 'harry@x').length, 2);
});

test('does not cache the plaintext password across dials', async () => {
  // After a reconnect, the password must come from the store again, so rotating
  // the stored credential is reflected on the next dial.
  const { registry, dials, clients, creds } = fixture();
  await registry.get('harry@x');
  clients.get('harry@x').forceUnusable();
  creds.put('harry@x', 'usagi', 993, 'new-pw');
  await registry.get('harry@x');
  assert.equal(dials[1].pass, 'new-pw');
});

test('treats a throwing CredentialStore.get as an unusable credential, not an opaque error', async () => {
  // CredentialStore.get can throw (e.g. AES-GCM tag verification failure on a
  // tampered/mismatched row) rather than only returning null. The registry must
  // surface that as CredentialUnavailableError, not let the raw error propagate,
  // and must not cache or return a connection.
  const creds = {
    get(_subject: string): { host: string; port: number; appPassword: string } | null {
      throw new Error('Unsupported state or unable to authenticate data');
    },
    put() {},
    markInvalid() {},
    touch() {},
  };
  const dials: Array<{ user: string; pass: string }> = [];
  const connector = (host: string, port: number, user: string, pass: string) => {
    dials.push({ user, pass });
    return { usable: false, connect: async () => {}, logout: async () => {} };
  };
  const registry = new TenantRegistry({ credentials: creds as any, connector });
  await assert.rejects(() => registry.get('harry@x'), CredentialUnavailableError);
  assert.equal(dials.length, 0);
});
