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
// Shared by every function here so none can drift out of sync with the
// others' idea of what counts as the marker phrase.
//
// \s* rather than \s+ between the words: stripping the invisible
// characters out of "UNTRUSTED<ZWSP>EMAIL<ZWSP>CONTENT" leaves the words
// butted together with no separator at all, and
// "--- END UNTRUSTEDEMAILCONTENT ---" still reads as the end marker.
// Nothing legitimate is caught by the difference.
const MARKER_PHRASE_PATTERN = /UNTRUSTED\s*EMAIL\s*CONTENT/gi;

// Characters that occupy no visual space and so can be sprinkled through
// the marker phrase to defeat a literal match while a reader -- human or
// model -- still sees "UNTRUSTED EMAIL CONTENT": zero-width space/joiners,
// bidi controls, word joiner, BOM, soft hyphen.
const INVISIBLE_PATTERN = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/**
 * Fold away the two cheap ways to write the marker phrase without matching
 * it: invisible characters between the words, and compatibility variants of
 * the letters themselves (full-width "ＵＮＴＲＵＳＴＥＤ", circled or
 * mathematical letterforms, and so on -- NFKC maps all of those to ASCII).
 *
 * This normalises the text that is actually emitted, not just a shadow copy
 * used for matching: defanging a match found in a normalised copy cannot be
 * mapped back onto the original's character offsets, and emitting the
 * original would leave the evasion intact. NFKC does alter a few visible
 * things (a full-width digit becomes an ASCII digit, a ligature is split),
 * which is an acceptable trade in output whose entire purpose is to be read
 * as text by a model.
 */
function normaliseInvisibles(value: string): string {
  return value.replace(INVISIBLE_PATTERN, '').normalize('NFKC');
}

/**
 * Neutralise any marker phrase in a string, however it was written.
 *
 * Applied to ASSEMBLED output, not only to individual fields: defanging
 * each field in isolation leaves the seam between them open, so a sender
 * who puts "... UNTRUSTED EMAIL" in one header and "CONTENT ..." in the
 * next reassembles the phrase in the rendered line while each field, on its
 * own, is clean. Every function in this module that composes text runs this
 * over the finished string.
 */
export function defangMarkerPhrase(value: string): string {
  return normaliseInvisibles(value).replace(MARKER_PHRASE_PATTERN, 'UNTRUSTED_EMAIL_CONTENT');
}

/**
 * Put message-derived text inside explicit untrusted-content markers.
 *
 * Anything derived from a message -- a body, a sender, a subject, an
 * attachment filename -- is attacker-controlled: anyone can mail these
 * mailboxes, and here the text is read by an agent with tools. Text that
 * arrives with no markers at all has no block for a sender to escape from
 * because there is no block, which is not the same as being safe: it is
 * simply presented as trusted. Every marker the sender embedded is defanged
 * first, over the assembled string, so the block cannot be closed early.
 */
export function wrapUntrusted(content: string): string {
  return `${BEGIN_MARKER}\n${defangMarkerPhrase(content)}\n${END_MARKER}`;
}

function clampBody(text: string, maxChars: number): { body: string; notice: string } {
  const defanged = defangMarkerPhrase(text);
  const truncated = defanged.length > maxChars;
  return {
    body: truncated ? defanged.slice(0, maxChars) : defanged,
    notice: truncated ? `\n[truncated at ${maxChars} characters]` : '',
  };
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
  // Defanged AGAIN over the assembled line, not just per field: a sender
  // ending "...UNTRUSTED EMAIL" and a subject starting "CONTENT..." are
  // each individually clean and reassemble into the phrase once joined.
  return defangMarkerPhrase(`${account} [${uid}] ${date}  ${sender}  ${subject}`);
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
  const { body, notice } = clampBody(text, maxChars);
  return `${wrapUntrusted(body)}${notice}`;
}

/**
 * A whole message -- its header block and its body -- inside ONE untrusted
 * block, with the truncation notice outside it.
 *
 * The header block belongs inside. From and Subject are attacker-controlled
 * to exactly the same degree as the body, so rendering them above the BEGIN
 * marker put them in the region the format presents as trusted: a sender
 * could say whatever they liked in the one part of the output a reader has
 * been told to believe. Only maxChars-worth of BODY is kept; the headers
 * are never dropped.
 */
export function formatMessage(header: string, body: string, maxChars: number): string {
  const { body: clamped, notice } = clampBody(body, maxChars);
  return `${wrapUntrusted(`${header}\n\n${clamped}`)}${notice}`;
}
