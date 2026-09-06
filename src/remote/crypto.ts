import { createCipheriv, createDecipheriv, randomBytes, createHash, timingSafeEqual } from 'node:crypto';

const NONCE_BYTES = 12;

export function encryptSecret(plaintext: string, key: Buffer, aad: string): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${nonce.toString('base64')}.${Buffer.concat([ct, tag]).toString('base64')}`;
}

export function decryptSecret(packed: string, key: Buffer, aad: string): string {
  const [nonceB64, bodyB64] = packed.split('.');
  if (!nonceB64 || !bodyB64) throw new Error('malformed ciphertext');
  const nonce = Buffer.from(nonceB64, 'base64');
  const body = Buffer.from(bodyB64, 'base64');
  const tag = body.subarray(body.length - 16);
  const ct = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
