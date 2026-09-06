// test/remote/env.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadRemoteConfig } from '../../src/remote/env.ts';

const base = { ISSUER_URL: 'https://mailcp.mizutech.id', KEY_PATH: '/etc/mailcp/key', DB_PATH: '/var/lib/mailcp/db.sqlite', MAILCOW_IMAP_HOST: 'usagi.mizutech.id' };

test('loads a full config with defaults', () => {
  const c = loadRemoteConfig(base);
  assert.equal(c.issuerUrl.href, 'https://mailcp.mizutech.id/');
  assert.equal(c.port, 8787);
  assert.equal(c.imapPort, 993);
});

test('rejects a missing issuer url', () => {
  assert.throws(() => loadRemoteConfig({ ...base, ISSUER_URL: undefined }), /ISSUER_URL/);
});

test('rejects a missing IMAP host', () => {
  assert.throws(() => loadRemoteConfig({ ...base, MAILCOW_IMAP_HOST: undefined }), /MAILCOW_IMAP_HOST/);
});

test('rejects a cleartext IMAP port (143)', () => {
  assert.throws(() => loadRemoteConfig({ ...base, MAILCOW_IMAP_PORT: '143' }), /cleartext|TLS/i);
});

test('rejects a cleartext IMAP port (110)', () => {
  assert.throws(() => loadRemoteConfig({ ...base, MAILCOW_IMAP_PORT: '110' }), /cleartext|TLS/i);
});
