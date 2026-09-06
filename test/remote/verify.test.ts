import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeImapVerifier } from '../../src/remote/verify.ts';

test('returns true when the connection succeeds', async () => {
  const calls: string[] = [];
  const verify = makeImapVerifier(() => ({
    connect: async () => { calls.push('connect'); },
    logout: async () => { calls.push('logout'); },
  }));
  assert.equal(await verify('usagi', 993, 'harry@x', 'pw'), true);
  assert.deepEqual(calls, ['connect', 'logout']);
});

test('returns false when the connection is refused', async () => {
  const verify = makeImapVerifier(() => ({
    connect: async () => { throw new Error('auth failed'); },
    logout: async () => {},
  }));
  assert.equal(await verify('usagi', 993, 'harry@x', 'bad'), false);
});

test('still returns true even if logout throws after a good connect', async () => {
  const verify = makeImapVerifier(() => ({
    connect: async () => {},
    logout: async () => { throw new Error('logout boom'); },
  }));
  assert.equal(await verify('usagi', 993, 'harry@x', 'pw'), true);
});

test('passes connection parameters through to the factory', async () => {
  let seen: unknown[] = [];
  const verify = makeImapVerifier((...args) => { seen = args; return { connect: async () => {}, logout: async () => {} }; });
  await verify('usagi', 993, 'harry@x', 'pw');
  assert.deepEqual(seen, ['usagi', 993, 'harry@x', 'pw']);
});
