export type SearchArgs = {
  from?: string;
  subject?: string;
  since?: string;
  unseen?: boolean;
};

/**
 * Translate tool arguments into an ImapFlow search object.
 * An empty query must become `{ all: true }` — ImapFlow treats `{}` as a match
 * for nothing, which would silently return an empty inbox.
 */
export function buildSearchQuery(args: SearchArgs): Record<string, unknown> {
  const query: Record<string, unknown> = {};

  if (args.from) query.from = args.from;
  if (args.subject) query.subject = args.subject;

  if (args.since) {
    const since = new Date(args.since);
    if (Number.isNaN(since.getTime())) {
      throw new Error(`since is not a parseable date: ${args.since}`);
    }
    query.since = since;
  }

  if (args.unseen) query.seen = false;

  return Object.keys(query).length > 0 ? query : { all: true };
}
