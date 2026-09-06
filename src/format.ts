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
// came from a structured field like Subject or From. Beyond CR/LF and the
// Unicode line/paragraph separators, this also collapses NEL (U+0085),
// vertical tab (\v, U+000B) and form feed (\f, U+000C) -- renderers and
// terminals vary on which of these they treat as a line break, so a value
// containing any of them is not safe to present as a single line either.
const LINE_BREAK_PATTERN = /\r\n|\r|\n|\u2028|\u2029|\u0085|\v|\f/g;

// The untrusted-content marker phrase, matched the way a model reading the
// surrounding text would recognise it -- not the way an exact byte-for-byte
// comparison would. Case-insensitive, and tolerant of any run of whitespace
// between the three words (a literal tab, doubled spaces, or a line break
// that slipped in before header values are collapsed to one line): a sender
// does not need an exact-case, single-spaced match to produce text a
// language model would still read as "--- END UNTRUSTED EMAIL CONTENT ---".
// Shared by sanitizeHeaderValue and formatBody so neither can drift out of
// sync with the other's idea of what counts as the marker phrase.
const MARKER_PHRASE_PATTERN = /UNTRUSTED\s+EMAIL\s+CONTENT/gi;

function defangMarkerPhrase(value: string): string {
  return value.replace(MARKER_PHRASE_PATTERN, 'UNTRUSTED_EMAIL_CONTENT');
}

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
  return defangMarkerPhrase(singleLine);
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
 * early and have the rest of itself read as instructions. Defanging shares
 * defangMarkerPhrase with sanitizeHeaderValue, so the body and header paths
 * cannot diverge on what counts as the marker phrase.
 */
export function formatBody(text: string, maxChars: number): string {
  const defanged = defangMarkerPhrase(text);

  const truncated = defanged.length > maxChars;
  const body = truncated ? defanged.slice(0, maxChars) : defanged;
  const notice = truncated ? `\n[truncated at ${maxChars} characters]` : '';

  return `${BEGIN_MARKER}\n${body}\n${END_MARKER}${notice}`;
}
