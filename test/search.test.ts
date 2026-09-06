import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSearchQuery, sinceError } from '../src/search.ts';

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

// ---------------------------------------------------------------------------
// sinceError: the pre-guard check. buildSearchQuery throws for the same
// input, but a throw from inside the tool's retry guard is classified as
// transient, so a permanent argument error reached the model as "try again
// in a moment" and it looped.
// ---------------------------------------------------------------------------

test('sinceError returns null when since is absent or parseable', () => {
  assert.equal(sinceError({}), null);
  assert.equal(sinceError({ since: '' }), null);
  assert.equal(sinceError({ since: '2026-01-31' }), null);
  assert.equal(sinceError({ since: '2026-01-31T00:00:00Z' }), null);
});

test('sinceError describes an unparseable since and says what a good one looks like', () => {
  const message = sinceError({ since: 'last tuesday' });
  assert.ok(message);
  assert.match(message!, /last tuesday/);
  assert.match(message!, /2026-01-31/, 'the message must show the expected shape, or the model cannot correct itself');
});

test('sinceError and buildSearchQuery agree on what is unparseable', () => {
  for (const since of ['last tuesday', 'not-a-date', '2026-13-45']) {
    assert.ok(sinceError({ since }), `sinceError should reject ${since}`);
    assert.throws(() => buildSearchQuery({ since }), `buildSearchQuery should reject ${since}`);
  }
  for (const since of ['2026-01-31', '2026-01-31T12:00:00Z']) {
    assert.equal(sinceError({ since }), null);
    assert.doesNotThrow(() => buildSearchQuery({ since }));
  }
});
