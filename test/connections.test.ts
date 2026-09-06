import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionRegistry, type Connectable } from '../src/connections.ts';
import type { Account } from '../src/config.ts';

const ACCOUNTS: Account[] = [
  { name: 'harry', host: 'a.tld', port: 993, user: 'harry@x.tld', password: 'pw' },
  { name: 'admin', host: 'b.tld', port: 993, user: 'admin@x.tld', password: 'pw2' },
];

function fakeConnector(opts: { failFirstConnect?: boolean } = {}) {
  const connects: string[] = [];
  const logouts: string[] = [];
  const clients = new Map<string, Connectable & { forceUnusable: () => void }>();
  let failures = opts.failFirstConnect ? 1 : 0;

  const connector = (account: Account) => {
    const client = {
      usable: false,
      connect: async () => {
        connects.push(account.name);
        if (failures > 0) { failures -= 1; throw new Error('connect refused'); }
        client.usable = true;
      },
      logout: async () => { logouts.push(account.name); client.usable = false; },
      forceUnusable: () => { client.usable = false; },
    };
    clients.set(account.name, client);
    return client;
  };

  return { connector, connects, logouts, clients };
}

test('names lists every configured account', () => {
  const { connector } = fakeConnector();
  assert.deepEqual(new ConnectionRegistry(ACCOUNTS, connector).names(), ['harry', 'admin']);
});

test('rejects an unknown account and names the valid ones', async () => {
  const { connector } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await assert.rejects(() => registry.get('nobody'), /nobody.*harry.*admin/s);
});

test('connects on first use', async () => {
  const { connector, connects } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await registry.get('harry');
  assert.deepEqual(connects, ['harry']);
});

test('does not connect accounts that were never used', async () => {
  const { connector, connects } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await registry.get('harry');
  assert.ok(!connects.includes('admin'));
});

test('reuses a live connection instead of reconnecting', async () => {
  const { connector, connects } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await registry.get('harry');
  await registry.get('harry');
  assert.deepEqual(connects, ['harry']);
});

test('reconnects when the connection went unusable', async () => {
  const { connector, connects, clients } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await registry.get('harry');
  clients.get('harry')!.forceUnusable();
  await registry.get('harry');
  assert.deepEqual(connects, ['harry', 'harry']);
});

test('concurrent first use connects only once', async () => {
  const { connector, connects } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await Promise.all([registry.get('harry'), registry.get('harry'), registry.get('harry')]);
  assert.deepEqual(connects, ['harry']);
});

test('a failed connect is not cached and the next call retries', async () => {
  const { connector, connects } = fakeConnector({ failFirstConnect: true });
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await assert.rejects(() => registry.get('harry'), /connect refused/);
  await registry.get('harry');
  assert.deepEqual(connects, ['harry', 'harry']);
});

test('closeAll logs out only the accounts that were connected', async () => {
  const { connector, logouts } = fakeConnector();
  const registry = new ConnectionRegistry(ACCOUNTS, connector);
  await registry.get('harry');
  await registry.closeAll();
  assert.deepEqual(logouts, ['harry']);
});
