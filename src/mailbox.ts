export type MailboxLock = { release: () => void };

export type ImapLike = {
  list: () => Promise<Array<{ path: string; specialUse?: string }>>;
  getMailboxLock: (path: string) => Promise<MailboxLock>;
  search: (query: Record<string, unknown>, opts: { uid: true }) => Promise<number[] | false>;
  fetch: (
    range: string | number[],
    query: Record<string, unknown>,
    opts: { uid: true },
  ) => AsyncIterable<any>;
};

/**
 * Run `fn` while holding an exclusive lock on `folder`.
 *
 * ImapFlow serialises all mailbox work behind this lock; leaking one wedges
 * every later request on the same connection, so release happens in `finally`.
 */
export async function withMailbox<T>(
  client: ImapLike,
  folder: string,
  fn: () => Promise<T>,
): Promise<T> {
  const lock = await client.getMailboxLock(folder);
  try {
    return await fn();
  } finally {
    lock.release();
  }
}

export async function listFolders(client: ImapLike): Promise<string[]> {
  const boxes = await client.list();
  return boxes.map((box) => box.path);
}

/**
 * UIDs matching `query` in `folder`, newest first, capped at `limit`.
 *
 * IMAP returns UIDs ascending and higher UID means more recently delivered,
 * so the newest results are the tail of the list, not the head.
 */
export async function searchSummaries(
  client: ImapLike,
  folder: string,
  query: Record<string, unknown>,
  limit: number,
): Promise<number[]> {
  return withMailbox(client, folder, async () => {
    const uids = await client.search(query, { uid: true });
    if (!uids || uids.length === 0) return [];
    return uids.slice(-limit).reverse();
  });
}

export type MessageSummary = { uid: number; envelope: Record<string, unknown> };

/**
 * Envelopes for `uids`, returned in the caller's order.
 *
 * The server streams results in its own order and may omit UIDs that were
 * expunged between the search and the fetch, so results are indexed by UID and
 * then replayed against the requested order.
 */
export async function fetchEnvelopes(
  client: ImapLike,
  folder: string,
  uids: number[],
): Promise<MessageSummary[]> {
  if (uids.length === 0) return [];

  return withMailbox(client, folder, async () => {
    const byUid = new Map<number, Record<string, unknown>>();
    for await (const message of client.fetch(uids, { envelope: true }, { uid: true })) {
      byUid.set(message.uid, message.envelope);
    }
    return uids
      .filter((uid) => byUid.has(uid))
      .map((uid) => ({ uid, envelope: byUid.get(uid)! }));
  });
}

/** Raw RFC822 source for one message, for the MIME parser to decode. */
export async function fetchMessageSource(
  client: ImapLike,
  folder: string,
  uid: number,
): Promise<Buffer> {
  return withMailbox(client, folder, async () => {
    for await (const message of client.fetch([uid], { source: true }, { uid: true })) {
      return message.source as Buffer;
    }
    throw new Error(`no message with uid ${uid} in ${folder}`);
  });
}
