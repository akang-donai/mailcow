export type Envelope = {
  date?: Date;
  subject?: string;
  from?: Array<{ name?: string; address?: string }>;
};

const BEGIN_MARKER = '--- BEGIN UNTRUSTED EMAIL CONTENT ---';
const END_MARKER = '--- END UNTRUSTED EMAIL CONTENT ---';

// Any of these can appear in a decoded RFC 2047 encoded-word (mailparser
// decodes those before we ever see the header value), so a header is not
// safe to treat as a single line of trusted-looking text just because it
// came from a structured field like Subject or From.
const LINE_BREAK_PATTERN = /\r\n|\r|\n|\u2028|\u2029/g;

/**
 * Make a single header value (a subject, a display name, an address) safe
 * to interpolate into output that is otherwise presented as trusted.
 *
 * Header values are attacker-controlled to the same degree as the message
 * body: anyone can mail this mailbox, and RFC 2047 encoded-words let a
 * sender put arbitrary bytes -- including raw CR/LF -- into a Subject or
 * From header. Left alone, that lets a single decoded header masquerade as
 * several lines of output, including a forged
 * "--- BEGIN/END UNTRUSTED EMAIL CONTENT ---" pair that fools a model
 * reading the surrounding text into treating its own output as trusted.
 *
 * Line breaks are collapsed to a space *before* the marker phrase is
 * defanged, not after, so a marker phrase deliberately split across an
 * injected line break (e.g. "UNTRUSTED EMAIL\r\nCONTENT") is still caught.
 */
export function sanitizeHeaderValue(value: string): string {
  const singleLine = value.replace(LINE_BREAK_PATTERN, ' ');
  return singleLine.split('UNTRUSTED EMAIL CONTENT').join('UNTRUSTED_EMAIL_CONTENT');
}

/**
 * One summary line, led by the account it came from.
 *
 * With several mailboxes configured the account is the only thing separating
 * two otherwise identical lines, so it is never omitted. The sender and
 * subject are attacker-controlled, so both pass through sanitizeHeaderValue
 * before they are interpolated.
 */
export function formatSummary(account: string, uid: number, envelope: Envelope): string {
  const date = envelope.date ? envelope.date.toISOString().slice(0, 10) : '(no date)';
  const sender = sanitizeHeaderValue(envelope.from?.[0]?.address ?? '(unknown sender)');
  const subject = sanitizeHeaderValue(envelope.subject || '(no subject)');
  return `${account} [${uid}] ${date}  ${sender}  ${subject}`;
}

/**
 * Wrap message text in explicit untrusted-content markers.
 *
 * Message bodies are attacker-controlled: anyone can mail this mailbox. The
 * markers tell the model where untrusted text starts and stops, and any
 * marker the sender embedded is defanged so a message cannot close the block
 * early and have the rest of itself read as instructions.
 */
export function formatBody(text: string, maxChars: number): string {
  const defanged = text.split('UNTRUSTED EMAIL CONTENT').join('UNTRUSTED_EMAIL_CONTENT');

  const truncated = defanged.length > maxChars;
  const body = truncated ? defanged.slice(0, maxChars) : defanged;
  const notice = truncated ? `\n[truncated at ${maxChars} characters]` : '';

  return `${BEGIN_MARKER}\n${body}\n${END_MARKER}${notice}`;
}
