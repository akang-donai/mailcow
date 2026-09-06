import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSearchQuery } from '../src/search.ts';

test('matches everything when no filters given', () => {
  assert.deepEqual(buildSearchQuery({}), { all: true });
});

test('passes from and subject through as substring filters', () => {
  assert.deepEqual(
    buildSearchQuery({ from: 'boss@mizutech.id', subject: 'invoice' }),
    { from: 'boss@mizutech.id', subject: 'invoice' },
  );
});

test('converts since date string to a Date', () => {
  const q = buildSearchQuery({ since: '2026-01-15' });
  assert.ok(q.since instanceof Date);
  assert.equal((q.since as Date).toISOString().slice(0, 10), '2026-01-15');
});

test('unseen true becomes seen false', () => {
  assert.deepEqual(buildSearchQuery({ unseen: true }), { seen: false });
});

test('unseen false does not constrain seen flag', () => {
  assert.deepEqual(buildSearchQuery({ unseen: false }), { all: true });
});

test('rejects an unparseable since date', () => {
  assert.throws(() => buildSearchQuery({ since: 'last tuesday' }), /since/);
});
