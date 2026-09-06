import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAccounts, assertSecureMode } from '../src/config.ts';

const one = (over: Record<string, unknown> = {}) => ({
  accounts: { harry: { host: 'usagi.mizutech.id', user: 'harry@x.tld', password: 'pw', ...over } },
});

test('parses an account and carries its name', () => {
  assert.deepEqual(parseAccounts(one()), [
    { name: 'harry', host: 'usagi.mizutech.id', port: 993, user: 'harry@x.tld', password: 'pw' },
  ]);
});

test('parses several accounts in declaration order', () => {
  const accounts = parseAccounts({
    accounts: {
      harry: { host: 'a.tld', user: 'harry@x.tld', password: 'pw' },
      admin: { host: 'b.tld', user: 'admin@x.tld', password: 'pw2' },
    },
  });
  assert.deepEqual(accounts.map((a) => a.name), ['harry', 'admin']);
  assert.equal(accounts[1].host, 'b.tld');
});

test('honours a per-account port', () => {
  assert.equal(parseAccounts(one({ port: 10993 }))[0].port, 10993);
});

test('rejects a cleartext port', () => {
  assert.throws(() => parseAccounts(one({ port: 143 })), /cleartext|TLS/i);
});

test('rejects a port outside the valid range', () => {
  assert.throws(() => parseAccounts(one({ port: 70000 })), /port/i);
});

test('rejects a file that is not an object', () => {
  assert.throws(() => parseAccounts('nope'), /object/i);
  assert.throws(() => parseAccounts(null), /object/i);
});

test('rejects a file with no accounts key', () => {
  assert.throws(() => parseAccounts({ mailboxes: {} }), /accounts/i);
});

test('rejects a file that configures zero accounts', () => {
  assert.throws(() => parseAccounts({ accounts: {} }), /at least one/i);
});

test('names the offending account when a field is missing', () => {
  assert.throws(() => parseAccounts({ accounts: { harry: { user: 'a@b.tld', password: 'pw' } } }), /harry.*host/i);
  assert.throws(() => parseAccounts({ accounts: { harry: { host: 'a.tld', password: 'pw' } } }), /harry.*user/i);
  assert.throws(() => parseAccounts({ accounts: { harry: { host: 'a.tld', user: 'a@b.tld' } } }), /harry.*password/i);
});

test('rejects an account whose value is not an object', () => {
  assert.throws(() => parseAccounts({ accounts: { harry: 'pw' } }), /harry/);
});

test('accepts owner-only file permissions', () => {
  assert.doesNotThrow(() => assertSecureMode(0o600, '/x/accounts.json'));
  assert.doesNotThrow(() => assertSecureMode(0o400, '/x/accounts.json'));
});

test('rejects a credentials file readable by group or others', () => {
  assert.throws(() => assertSecureMode(0o644, '/x/accounts.json'), /permission|0600/i);
  assert.throws(() => assertSecureMode(0o640, '/x/accounts.json'), /permission|0600/i);
});

test('ignores file type bits when checking permissions', () => {
  assert.doesNotThrow(() => assertSecureMode(0o100600, '/x/accounts.json'));
});

test('permission error names the offending path', () => {
  assert.throws(() => assertSecureMode(0o644, '/x/accounts.json'), /\/x\/accounts\.json/);
});
