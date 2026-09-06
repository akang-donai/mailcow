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

// ---------------------------------------------------------------------------
// BIND_ADDR. The listener's bind address is configurable because a container
// published as 127.0.0.1:8787:8787 DNATs to the container's *bridge*
// address -- a process bound to the container's own loopback is unreachable
// through that mapping, so nginx gets connection-refused on every request
// while the in-container healthcheck (which does use loopback) still passes.
// Bare-metal use must stay loopback-only, so that is the default.
// ---------------------------------------------------------------------------

test('bind address defaults to loopback when BIND_ADDR is not set', () => {
  assert.equal(loadRemoteConfig(base).bindAddr, '127.0.0.1');
});

test('accepts BIND_ADDR 0.0.0.0, which is what the container needs', () => {
  assert.equal(loadRemoteConfig({ ...base, BIND_ADDR: '0.0.0.0' }).bindAddr, '0.0.0.0');
});

test('accepts an explicit loopback and an IPv6 bind address', () => {
  assert.equal(loadRemoteConfig({ ...base, BIND_ADDR: '127.0.0.1' }).bindAddr, '127.0.0.1');
  assert.equal(loadRemoteConfig({ ...base, BIND_ADDR: '::' }).bindAddr, '::');
  assert.equal(loadRemoteConfig({ ...base, BIND_ADDR: '::1' }).bindAddr, '::1');
});

test('rejects a BIND_ADDR that is not an IP literal', () => {
  // A hostname is resolved by listen() at startup, so a DNS or hosts-file
  // change could silently move the listener to a wider interface. Refused
  // outright rather than resolved.
  assert.throws(() => loadRemoteConfig({ ...base, BIND_ADDR: 'localhost' }), /BIND_ADDR/);
  assert.throws(() => loadRemoteConfig({ ...base, BIND_ADDR: 'not an address' }), /BIND_ADDR/);
  assert.throws(() => loadRemoteConfig({ ...base, BIND_ADDR: '' }), /BIND_ADDR/);
  assert.throws(() => loadRemoteConfig({ ...base, BIND_ADDR: '999.1.1.1' }), /BIND_ADDR/);
});

// ---------------------------------------------------------------------------
// SMTP scope probe configuration (see src/remote/consent.ts).
// ---------------------------------------------------------------------------

test('SMTP probe defaults to the IMAP host on port 465', () => {
  const c = loadRemoteConfig(base);
  assert.equal(c.smtpHost, 'usagi.mizutech.id');
  assert.equal(c.smtpPort, 465);
});

test('SMTP host and port can be overridden independently of IMAP', () => {
  const c = loadRemoteConfig({ ...base, MAILCOW_SMTP_HOST: 'smtp.elsewhere.test', MAILCOW_SMTP_PORT: '10465' });
  assert.equal(c.smtpHost, 'smtp.elsewhere.test');
  assert.equal(c.smtpPort, 10465);
});

test('rejects an out-of-range SMTP port', () => {
  assert.throws(() => loadRemoteConfig({ ...base, MAILCOW_SMTP_PORT: '70000' }), /MAILCOW_SMTP_PORT/);
});
