import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.ts';

test('rejects config with no IMAP host', () => {
  assert.throws(
    () => loadConfig({ MAILCOW_IMAP_USER: 'me@x.tld', MAILCOW_IMAP_PASSWORD: 'pw' }),
    /MAILCOW_IMAP_HOST/,
  );
});

test('rejects config with no IMAP user', () => {
  assert.throws(
    () => loadConfig({ MAILCOW_IMAP_HOST: 'usagi.mizutech.id', MAILCOW_IMAP_PASSWORD: 'pw' }),
    /MAILCOW_IMAP_USER/,
  );
});

test('rejects config with no IMAP password', () => {
  assert.throws(
    () => loadConfig({ MAILCOW_IMAP_HOST: 'usagi.mizutech.id', MAILCOW_IMAP_USER: 'me@x.tld' }),
    /MAILCOW_IMAP_PASSWORD/,
  );
});

test('defaults to implicit-TLS port 993', () => {
  const cfg = loadConfig({
    MAILCOW_IMAP_HOST: 'usagi.mizutech.id',
    MAILCOW_IMAP_USER: 'me@x.tld',
    MAILCOW_IMAP_PASSWORD: 'pw',
  });
  assert.equal(cfg.port, 993);
});

test('rejects plaintext IMAP port 143', () => {
  assert.throws(
    () => loadConfig({
      MAILCOW_IMAP_HOST: 'usagi.mizutech.id',
      MAILCOW_IMAP_USER: 'me@x.tld',
      MAILCOW_IMAP_PASSWORD: 'pw',
      MAILCOW_IMAP_PORT: '143',
    }),
    /TLS/,
  );
});
