import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { encryptSecret, decryptSecret, randomToken, hashToken, timingSafeEqualHex } from '../../src/remote/crypto.ts';

const key = randomBytes(32);

test('round-trips a secret under the same subject', () => {
  const packed = encryptSecret('app-password', key, 'harry@mizutech.id');
  assert.equal(decryptSecret(packed, key, 'harry@mizutech.id'), 'app-password');
});

test('ciphertext is not the plaintext and carries a nonce segment', () => {
  const packed = encryptSecret('app-password', key, 'harry@mizutech.id');
  assert.ok(!packed.includes('app-password'));
  assert.equal(packed.split('.').length, 2);
});

test('two encryptions of the same input differ (fresh nonce)', () => {
  assert.notEqual(
    encryptSecret('x', key, 'harry@mizutech.id'),
    encryptSecret('x', key, 'harry@mizutech.id'),
  );
});

test('decryption fails when the AAD subject differs', () => {
  const packed = encryptSecret('app-password', key, 'harry@mizutech.id');
  assert.throws(() => decryptSecret(packed, key, 'dea@mizutech.id'));
});

test('decryption fails under the wrong key', () => {
  const packed = encryptSecret('app-password', key, 'harry@mizutech.id');
  assert.throws(() => decryptSecret(packed, randomBytes(32), 'harry@mizutech.id'));
});

test('decryption fails when ciphertext is tampered', () => {
  const packed = encryptSecret('app-password', key, 'harry@mizutech.id');
  const [n, c] = packed.split('.');
  const bytes = Buffer.from(c, 'base64'); bytes[0] ^= 0xff;
  assert.throws(() => decryptSecret(`${n}.${bytes.toString('base64')}`, key, 'harry@mizutech.id'));
});

test('randomToken is 43-char base64url and unique', () => {
  const a = randomToken(), b = randomToken();
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a, b);
});

test('hashToken is deterministic 64-hex and hides the input', () => {
  assert.match(hashToken('t'), /^[0-9a-f]{64}$/);
  assert.equal(hashToken('t'), hashToken('t'));
  assert.notEqual(hashToken('t'), hashToken('u'));
});

test('timingSafeEqualHex compares equal and unequal hex of same length', () => {
  assert.equal(timingSafeEqualHex(hashToken('t'), hashToken('t')), true);
  assert.equal(timingSafeEqualHex(hashToken('t'), hashToken('u')), false);
});

test('timingSafeEqualHex is false for different-length inputs, no throw', () => {
  assert.equal(timingSafeEqualHex('aa', 'aabb'), false);
});
