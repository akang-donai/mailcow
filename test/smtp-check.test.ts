import { test } from 'node:test';
import assert from 'node:assert/strict';
import { interpretAuthResponse } from '../src/smtp-check.ts';

test('535 authentication failure means the credential was rejected', () => {
  assert.equal(interpretAuthResponse('535 5.7.8 Error: authentication failed'), 'rejected');
});

test('534 and 454 auth errors also count as rejected', () => {
  assert.equal(interpretAuthResponse('534 5.7.9 Please use a mechanism'), 'rejected');
  assert.equal(interpretAuthResponse('454 4.7.0 Temporary authentication failure'), 'rejected');
});

test('235 means the credential was accepted, which is a failed security check', () => {
  assert.equal(interpretAuthResponse('235 2.7.0 Authentication successful'), 'accepted');
});

test('an unrecognised reply is not reported as rejected', () => {
  assert.equal(interpretAuthResponse('220 mail.example.com ESMTP'), 'unknown');
});

test('a blank reply is not reported as rejected', () => {
  assert.equal(interpretAuthResponse(''), 'unknown');
});

import { scopeVerdict } from '../src/smtp-check.ts';

test('a credential that works on IMAP and is refused on SMTP is correctly scoped', () => {
  assert.equal(scopeVerdict(true, 'rejected'), 'scoped');
});

test('a credential that works on both can send mail', () => {
  assert.equal(scopeVerdict(true, 'accepted'), 'can-send');
});

test('SMTP rejection proves nothing when IMAP also refused the credential', () => {
  assert.equal(scopeVerdict(false, 'rejected'), 'bad-credential');
});

test('an unreadable SMTP reply is inconclusive even with a working credential', () => {
  assert.equal(scopeVerdict(true, 'unknown'), 'inconclusive');
});

test('a credential IMAP refused but SMTP accepted is not reported as scoped', () => {
  assert.notEqual(scopeVerdict(false, 'accepted'), 'scoped');
});
