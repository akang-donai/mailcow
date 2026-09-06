/**
 * Security check: prove the app password CANNOT authenticate to SMTP.
 *
 * Reuses the same env vars as the server. Exits non-zero unless the server
 * refuses the credential.
 *   node scripts/check-no-smtp.ts
 */
import tls from 'node:tls';
import { loadConfig } from '../src/config.ts';
import { interpretAuthResponse } from '../src/smtp-check.ts';

const config = loadConfig(process.env);
const port = Number(process.env.MAILCOW_SMTP_PORT ?? 465);

const b64 = (s: string) => Buffer.from(s).toString('base64');

const outcome = await new Promise<string>((resolve, reject) => {
  const socket = tls.connect({ host: config.host, port, servername: config.host }, () => {});
  const steps = [
    `EHLO mcp-check`,
    `AUTH LOGIN`,
    b64(config.user),
    b64(config.password),
  ];
  let step = -1;
  let buffer = '';

  socket.setTimeout(15000, () => { socket.destroy(); reject(new Error('SMTP check timed out')); });
  socket.on('error', reject);

  socket.on('data', (chunk) => {
    buffer += chunk.toString();
    // Wait for a complete reply: last line must not be a multiline continuation.
    const lines = buffer.trimEnd().split(/\r?\n/);
    if (/^\d{3}-/.test(lines.at(-1)!)) return;

    const last = lines.at(-1)!;
    if (step === steps.length - 1) {
      socket.end();
      resolve(last);
      return;
    }
    buffer = '';
    step += 1;
    socket.write(steps[step] + '\r\n');
  });
});

const verdict = interpretAuthResponse(outcome);
console.log(`server replied: ${outcome}`);
console.log(`verdict: ${verdict}`);

if (verdict === 'rejected') {
  console.log('PASS - app password cannot send mail');
} else {
  console.log('FAIL - this credential is NOT restricted to IMAP; fix its scope in mailcow');
  process.exit(1);
}
