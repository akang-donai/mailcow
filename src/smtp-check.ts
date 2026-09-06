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
