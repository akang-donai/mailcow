/**
 * Live check against the real server.
 *   node scripts/smoke.ts            # every configured account
 *   node scripts/smoke.ts harry      # one account
 */
import { ImapFlow } from 'imapflow';
import { loadAccounts } from '../src/config.ts';
import { listFolders, searchSummaries, fetchEnvelopes, type ImapLike } from '../src/mailbox.ts';
import { formatSummary } from '../src/format.ts';

const wanted = process.argv[2];
const accounts = loadAccounts(process.env).filter((a) => !wanted || a.name === wanted);

if (accounts.length === 0) {
  console.error(`no account named "${wanted}"`);
  process.exit(1);
}

let failed = 0;

for (const account of accounts) {
  const client = new ImapFlow({
    host: account.host,
    port: account.port,
    secure: true,
    auth: { user: account.user, pass: account.password },
    logger: false,
  });

  try {
    await client.connect();
    console.log(`\n${account.name}: connected as ${account.user} via ${account.host}:${account.port}`);

    const imap = client as unknown as ImapLike;
    const folders = await listFolders(imap);
    console.log(`${account.name}: ${folders.length} folders — ${folders.join(', ')}`);

    const uids = await searchSummaries(imap, 'INBOX', { all: true }, 3);
    for (const m of await fetchEnvelopes(imap, 'INBOX', uids)) {
      console.log('  ' + formatSummary(account.name, m.uid, m.envelope as never));
    }
    await client.logout();
  } catch (err) {
    failed += 1;
    console.error(`${account.name}: FAILED — ${(err as Error).message}`);
  }
}

console.log(failed === 0 ? '\nOK' : `\n${failed} account(s) failed`);
process.exit(failed === 0 ? 0 : 1);
