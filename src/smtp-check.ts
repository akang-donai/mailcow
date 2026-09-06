export type AuthOutcome = 'rejected' | 'accepted' | 'unknown';

/** SMTP replies that mean the credential was refused (RFC 4954 §6). */
const REJECT_CODES = new Set(['535', '534', '454', '530', '538']);

/**
 * Classify an SMTP reply to AUTH.
 *
 * Anything unrecognised is `unknown`, never `rejected` — a security check must
 * not report success just because it failed to understand the answer.
 */
export function interpretAuthResponse(line: string): AuthOutcome {
  const code = line.trim().slice(0, 3);
  if (REJECT_CODES.has(code)) return 'rejected';
  if (code === '235') return 'accepted';
  return 'unknown';
}

export type ScopeVerdict = 'scoped' | 'can-send' | 'bad-credential' | 'inconclusive';

/**
 * Decide whether a credential is genuinely restricted to IMAP.
 *
 * SMTP refusing the credential only proves something if the credential is
 * known good: a typo is refused everywhere and would otherwise look like a
 * perfectly scoped app password. So the IMAP leg is a precondition, not a
 * convenience.
 */
export function scopeVerdict(imapAuthOk: boolean, smtp: AuthOutcome): ScopeVerdict {
  if (!imapAuthOk) return 'bad-credential';
  if (smtp === 'rejected') return 'scoped';
  if (smtp === 'accepted') return 'can-send';
  return 'inconclusive';
}

// ---------------------------------------------------------------------------
// The probe itself.
//
// This lives here, next to the two functions that interpret its result,
// because two callers need it: scripts/check-no-smtp.ts (Step A's accounts
// file) and the consent handler (which has no access to that file -- it
// holds encrypted per-subject rows instead). A second implementation would
// be a second thing to get wrong.
// ---------------------------------------------------------------------------
import tls from 'node:tls';

const b64 = (s: string) => Buffer.from(s).toString('base64');

export type SmtpAuthRequest = { host: string; port: number; user: string; password: string; timeoutMs?: number };

/**
 * Attempt AUTH LOGIN over implicit TLS and return the server's final reply
 * line, for interpretAuthResponse to classify.
 *
 * Rejects rather than resolving if the endpoint cannot be reached, does not
 * speak implicit TLS, or hangs up early: "no answer" is not an answer, and
 * callers must be able to tell it apart from a refusal.
 */
export function smtpAuthReply(req: SmtpAuthRequest): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: req.host, port: req.port, servername: req.host });
    const steps = ['EHLO mcp-check', 'AUTH LOGIN', b64(req.user), b64(req.password)];
    let step = -1;
    let buffer = '';
    let settled = false;

    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    socket.setTimeout(req.timeoutMs ?? 15000, () => {
      socket.destroy();
      finish(() => reject(new Error('SMTP check timed out')));
    });
    socket.on('error', (err) => finish(() => reject(err)));
    // Without this, a server that closes the connection mid-handshake leaves
    // the promise pending forever and the caller hanging.
    socket.on('close', () => finish(() => reject(new Error('SMTP connection closed before the AUTH reply'))));
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.trimEnd().split(/\r?\n/);
      if (/^\d{3}-/.test(lines.at(-1)!)) return;   // multiline reply still arriving
      const last = lines.at(-1)!;
      if (step === steps.length - 1) {
        socket.end();
        finish(() => resolve(last));
        return;
      }
      buffer = '';
      step += 1;
      socket.write(steps[step] + '\r\n');
    });
  });
}

/**
 * A credential's SMTP AUTH outcome, or 'unknown' if SMTP could not be
 * reached or understood.
 *
 * Unreachable is deliberately 'unknown', never 'rejected': a mailcow with
 * SMTP disabled, firewalled, or on a STARTTLS-only port would otherwise
 * make every credential look perfectly scoped.
 */
export type SmtpProbe = (host: string, port: number, user: string, password: string) => Promise<AuthOutcome>;

export function makeSmtpProbe(opts: { timeoutMs?: number; log?: (message: string) => void } = {}): SmtpProbe {
  return async (host, port, user, password) => {
    try {
      return interpretAuthResponse(await smtpAuthReply({ host, port, user, password, timeoutMs: opts.timeoutMs }));
    } catch (err) {
      opts.log?.(`SMTP scope probe could not reach ${host}:${port}: ${err instanceof Error ? err.message : String(err)}`);
      return 'unknown';
    }
  };
}
