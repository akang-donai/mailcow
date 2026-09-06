/**
 * Security check: every configured credential must read mail and be unable to send.
 *
 * Both legs matter. A wrong password is refused by SMTP too, so an SMTP
 * refusal only means something once IMAP has confirmed the credential is good.
 *
 *   node scripts/check-no-smtp.ts          # every account
 *   node scripts/check-no-smtp.ts harry    # one account
 */
import { ImapFlow } from 'imapflow';
import { loadAccounts, type Account } from '../src/config.ts';
import { interpretAuthResponse, scopeVerdict, smtpAuthReply } from '../src/smtp-check.ts';

const SMTP_PORT = Number(process.env.MAILCOW_SMTP_PORT ?? 465);

async function imapAccepts(account: Account): Promise<boolean> {
  const client = new ImapFlow({
    host: account.host,
    port: account.port,
    secure: true,
    auth: { user: account.user, pass: account.password },
    logger: false,
  });
  try {
    await client.connect();
    await client.logout();
    return true;
  } catch {
    return false;
  }
}


const wanted = process.argv[2];
const accounts = loadAccounts(process.env).filter((a) => !wanted || a.name === wanted);

if (accounts.length === 0) {
  console.error(`no account named "${wanted}"`);
  process.exit(1);
}

const MESSAGES = {
  'scoped': 'PASS - reads mail, cannot send',
  'can-send': 'FAIL - this credential CAN send mail; untick smtp_access on the app password',
  'bad-credential': 'INVALID - IMAP refused this credential, so the SMTP result proves nothing',
  'inconclusive': 'INVALID - could not classify the SMTP reply',
} as const;

let failed = 0;

for (const account of accounts) {
  const imapOk = await imapAccepts(account);
  const reply = await smtpAuthReply({ host: account.host, port: SMTP_PORT, user: account.user, password: account.password });
  const verdict = scopeVerdict(imapOk, interpretAuthResponse(reply));

  console.log(`\n${account.name} (${account.user})`);
  console.log(`  imap ${account.port}: ${imapOk ? 'authenticated' : 'refused'}`);
  console.log(`  smtp ${SMTP_PORT}: ${reply}`);
  console.log(`  verdict: ${verdict} — ${MESSAGES[verdict]}`);

  if (verdict !== 'scoped') failed += 1;
}

console.log(failed === 0 ? '\nAll accounts scoped read-only.' : `\n${failed} account(s) not safely scoped.`);
process.exit(failed === 0 ? 0 : 1);
