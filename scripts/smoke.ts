/**
 * Live end-to-end check against the real mailbox.
 * Usage: set the MAILCOW_IMAP_* env vars, then `node scripts/smoke.ts`
 */
import { ImapFlow } from 'imapflow';
import { loadConfig } from '../src/config.ts';
import { listFolders, searchSummaries, fetchEnvelopes, type ImapLike } from '../src/mailbox.ts';
import { formatSummary } from '../src/format.ts';

const config = loadConfig(process.env);
const client = new ImapFlow({
  host: config.host,
  port: config.port,
  secure: true,
  auth: { user: config.user, pass: config.password },
  logger: false,
});

await client.connect();
console.log(`connected: ${config.user}@${config.host}:${config.port}`);

const imap = client as unknown as ImapLike;

const folders = await listFolders(imap);
console.log(`folders (${folders.length}): ${folders.join(', ')}`);

const uids = await searchSummaries(imap, 'INBOX', { all: true }, 3);
const messages = await fetchEnvelopes(imap, 'INBOX', uids);
console.log(`newest ${messages.length} in INBOX:`);
for (const m of messages) console.log('  ' + formatSummary(m.uid, m.envelope as never));

await client.logout();
console.log('OK');
