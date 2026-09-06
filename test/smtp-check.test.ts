import { test } from 'node:test';
import assert from 'node:assert/strict';
import { interpretAuthResponse, makeSmtpProbe } from '../src/smtp-check.ts';

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

// ---------------------------------------------------------------------------
// makeSmtpProbe: the wrapper the consent handler uses. It must never turn a
// connection failure into either verdict -- 'unknown' is the only honest
// answer, and scopeVerdict maps that to 'inconclusive', which is permissive.
// ---------------------------------------------------------------------------

test('makeSmtpProbe reports unknown, and logs, when SMTP cannot be reached at all', async () => {
  const logged: string[] = [];
  // Port 1 on loopback: nothing listens, so tls.connect fails immediately.
  const probe = makeSmtpProbe({ timeoutMs: 2000, log: (m) => logged.push(m) });

  const outcome = await probe('127.0.0.1', 1, 'harry@x', 'pw');

  assert.equal(outcome, 'unknown');
  assert.equal(scopeVerdict(true, outcome), 'inconclusive', 'unreachable must not block enrolment');
  assert.equal(logged.length, 1);
  assert.match(logged[0]!, /127\.0\.0\.1:1/);
});

test('an unreachable probe is never reported as scoped', async () => {
  const probe = makeSmtpProbe({ timeoutMs: 2000 });
  const outcome = await probe('127.0.0.1', 1, 'harry@x', 'pw');
  assert.notEqual(scopeVerdict(true, outcome), 'scoped', 'a security check must not pass because it failed to run');
});
