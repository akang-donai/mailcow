export type Envelope = {
  date?: Date;
  subject?: string;
  from?: Array<{ name?: string; address?: string }>;
};

const BEGIN_MARKER = '--- BEGIN UNTRUSTED EMAIL CONTENT ---';
const END_MARKER = '--- END UNTRUSTED EMAIL CONTENT ---';

export function formatSummary(uid: number, envelope: Envelope): string {
  const date = envelope.date ? envelope.date.toISOString().slice(0, 10) : '(no date)';
  const sender = envelope.from?.[0]?.address ?? '(unknown sender)';
  const subject = envelope.subject || '(no subject)';
  return `[${uid}] ${date}  ${sender}  ${subject}`;
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
