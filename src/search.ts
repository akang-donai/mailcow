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
/**
 * Why `since` is unparseable, or null if it is fine (or absent).
 *
 * buildSearchQuery throws for the same input, but a throw from inside a
 * tool's retry guard is reported to the model as a transient failure --
 * "try again in a moment" -- for what is a permanent argument error, so it
 * retries the identical call forever. Callers check this BEFORE entering
 * the guard and return a permanent error instead.
 */
export function sinceError(args: SearchArgs): string | null {
  if (!args.since) return null;
  return Number.isNaN(new Date(args.since).getTime())
    ? `\`since\` is not a date I can parse: "${args.since}". Use an ISO-8601 date such as 2026-01-31 or 2026-01-31T00:00:00Z.`
    : null;
}

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
