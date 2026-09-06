/**
 * Security check: prove the credential works for IMAP and CANNOT send over SMTP.
 *
 * Both legs matter. A wrong password is refused by SMTP too, so the SMTP
 * refusal only means something once IMAP has confirmed the credential is good.
 *
 *   node scripts/check-no-smtp.ts
 */
import tls from 'node:tls';
import { ImapFlow } from 'imapflow';
import { loadConfig } from '../src/config.ts';
import { interpretAuthResponse, scopeVerdict } from '../src/smtp-check.ts';

const config = loadConfig(process.env);
const smtpPort = Number(process.env.MAILCOW_SMTP_PORT ?? 465);
const b64 = (s: string) => Buffer.from(s).toString('base64');

// Leg 1: the credential must actually work for IMAP.
const imap = new ImapFlow({
  host: config.host,
  port: config.port,
  secure: true,
  auth: { user: config.user, pass: config.password },
  logger: false,
});

let imapAuthOk = false;
try {
  await imap.connect();
  imapAuthOk = true;
  await imap.logout();
} catch (err) {
  console.log(`IMAP auth failed: ${(err as Error).message}`);
}
console.log(`imap ${config.port}: ${imapAuthOk ? 'authenticated' : 'refused'}`);

// Leg 2: the same credential must be refused by SMTP.
const smtpReply = await new Promise<string>((resolve, reject) => {
  const socket = tls.connect({ host: config.host, port: smtpPort, servername: config.host });
  const steps = ['EHLO mcp-check', 'AUTH LOGIN', b64(config.user), b64(config.password)];
  let step = -1;
  let buffer = '';

  socket.setTimeout(15000, () => { socket.destroy(); reject(new Error('SMTP check timed out')); });
  socket.on('error', reject);
  socket.on('data', (chunk) => {
    buffer += chunk.toString();
    const lines = buffer.trimEnd().split(/\r?\n/);
    if (/^\d{3}-/.test(lines.at(-1)!)) return;   // multiline reply still arriving
    const last = lines.at(-1)!;
    if (step === steps.length - 1) { socket.end(); resolve(last); return; }
    buffer = '';
    step += 1;
    socket.write(steps[step] + '\r\n');
  });
});

const smtpOutcome = interpretAuthResponse(smtpReply);
console.log(`smtp ${smtpPort}: ${smtpReply}`);

const verdict = scopeVerdict(imapAuthOk, smtpOutcome);
const messages: Record<typeof verdict, string> = {
  'scoped': 'PASS - credential reads mail but cannot send',
  'can-send': 'FAIL - this credential CAN send mail; untick smtp_access on the app password',
  'bad-credential': 'INVALID - IMAP refused this credential, so the SMTP result proves nothing',
  'inconclusive': `INVALID - could not classify the SMTP reply: ${smtpReply}`,
};
console.log(`verdict: ${verdict}`);
console.log(messages[verdict]);
process.exit(verdict === 'scoped' ? 0 : 1);
