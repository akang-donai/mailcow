import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withMailbox, listFolders, searchSummaries, fetchEnvelopes, fetchMessageSource } from '../src/mailbox.ts';

function fakeClient(overrides: Record<string, unknown> = {}) {
  const released: string[] = [];
  const locked: string[] = [];
  const client = {
    released,
    locked,
    list: async () => [
      { path: 'INBOX', specialUse: '\\Inbox' },
      { path: 'Sent', specialUse: '\\Sent' },
      { path: 'Projects/Mailcow' },
    ],
    getMailboxLock: async (path: string) => {
      locked.push(path);
      return { release: () => released.push(path) };
    },
    search: async () => [],
    fetch: async function* () {},
    ...overrides,
  };
  return client as any;
}

test('listFolders returns every mailbox path', async () => {
  assert.deepEqual(await listFolders(fakeClient()), ['INBOX', 'Sent', 'Projects/Mailcow']);
});

test('withMailbox locks the requested folder', async () => {
  const client = fakeClient();
  await withMailbox(client, 'INBOX', async () => 'done');
  assert.deepEqual(client.locked, ['INBOX']);
});

test('withMailbox releases the lock after success', async () => {
  const client = fakeClient();
  const result = await withMailbox(client, 'INBOX', async () => 'done');
  assert.equal(result, 'done');
  assert.deepEqual(client.released, ['INBOX']);
});

test('withMailbox releases the lock when the operation throws', async () => {
  const client = fakeClient();
  await assert.rejects(
    () => withMailbox(client, 'INBOX', async () => { throw new Error('boom'); }),
    /boom/,
  );
  assert.deepEqual(client.released, ['INBOX']);
});

test('searchSummaries returns newest uids first', async () => {
  const client = fakeClient({ search: async () => [1, 5, 9, 12] });
  assert.deepEqual(await searchSummaries(client, 'INBOX', { all: true }, 10), [12, 9, 5, 1]);
});

test('searchSummaries caps results at the limit, keeping the newest', async () => {
  const client = fakeClient({ search: async () => [1, 5, 9, 12] });
  assert.deepEqual(await searchSummaries(client, 'INBOX', { all: true }, 2), [12, 9]);
});

test('searchSummaries returns nothing when the server reports no matches', async () => {
  const client = fakeClient({ search: async () => false });
  assert.deepEqual(await searchSummaries(client, 'INBOX', { all: true }, 10), []);
});

test('searchSummaries releases the mailbox lock', async () => {
  const client = fakeClient({ search: async () => [3] });
  await searchSummaries(client, 'INBOX', { all: true }, 10);
  assert.deepEqual(client.released, ['INBOX']);
});

test('fetchEnvelopes preserves the requested uid order', async () => {
  const client = fakeClient({
    fetch: async function* () {
      yield { uid: 5, envelope: { subject: 'five' } };
      yield { uid: 12, envelope: { subject: 'twelve' } };
    },
  });
  const out = await fetchEnvelopes(client, 'INBOX', [12, 5]);
  assert.deepEqual(out.map((m) => m.uid), [12, 5]);
  assert.equal(out[0].envelope.subject, 'twelve');
});

test('fetchEnvelopes skips uids the server did not return', async () => {
  const client = fakeClient({
    fetch: async function* () {
      yield { uid: 5, envelope: { subject: 'five' } };
    },
  });
  assert.deepEqual(await fetchEnvelopes(client, 'INBOX', [12, 5]), [
    { uid: 5, envelope: { subject: 'five' } },
  ]);
});

test('fetchEnvelopes does no round trip for an empty uid list', async () => {
  let called = false;
  const client = fakeClient({ fetch: async function* () { called = true; } });
  assert.deepEqual(await fetchEnvelopes(client, 'INBOX', []), []);
  assert.equal(called, false);
});

test('fetchEnvelopes releases the mailbox lock', async () => {
  const client = fakeClient({
    fetch: async function* () { yield { uid: 5, envelope: {} }; },
  });
  await fetchEnvelopes(client, 'INBOX', [5]);
  assert.deepEqual(client.released, ['INBOX']);
});

test('fetchMessageSource returns the raw rfc822 source', async () => {
  const client = fakeClient({
    fetch: async function* () { yield { uid: 5, source: Buffer.from('Subject: hi\r\n\r\nbody') }; },
  });
  const src = await fetchMessageSource(client, 'INBOX', 5);
  assert.equal(src.toString(), 'Subject: hi\r\n\r\nbody');
});

test('fetchMessageSource reports a uid that no longer exists', async () => {
  const client = fakeClient({ fetch: async function* () {} });
  await assert.rejects(() => fetchMessageSource(client, 'INBOX', 999), /999/);
});

test('fetchMessageSource releases the lock when the uid is missing', async () => {
  const client = fakeClient({ fetch: async function* () {} });
  await assert.rejects(() => fetchMessageSource(client, 'INBOX', 999));
  assert.deepEqual(client.released, ['INBOX']);
});
