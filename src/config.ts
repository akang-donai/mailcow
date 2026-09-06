import { readFileSync, statSync } from 'node:fs';

export type Account = {
  name: string;
  host: string;
  port: number;
  user: string;
  password: string;
};

/** Ports that speak cleartext IMAP/POP3. This server only does implicit TLS. */
const PLAINTEXT_PORTS = new Set([110, 143]);

const DEFAULT_PORT = 993;

function requireString(
  account: Record<string, unknown>,
  name: string,
  field: string,
): string {
  const value = account[field];
  if (typeof value !== 'string' || value === '') {
    throw new Error(`account "${name}" is missing ${field}`);
  }
  return value;
}

function resolvePort(account: Record<string, unknown>, name: string): number {
  if (account.port === undefined) return DEFAULT_PORT;

  const port = Number(account.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`account "${name}" has an invalid port: ${account.port}`);
  }
  if (PLAINTEXT_PORTS.has(port)) {
    throw new Error(`account "${name}" uses cleartext port ${port}; implicit TLS is required`);
  }
  return port;
}

export function parseAccounts(raw: unknown): Account[] {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('accounts file must contain a JSON object');
  }

  const accounts = (raw as Record<string, unknown>).accounts;
  if (typeof accounts !== 'object' || accounts === null || Array.isArray(accounts)) {
    throw new Error('accounts file must contain an "accounts" object');
  }

  const entries = Object.entries(accounts as Record<string, unknown>);
  if (entries.length === 0) {
    throw new Error('accounts file must define at least one account');
  }

  return entries.map(([name, value]) => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new Error(`account "${name}" must be an object`);
    }
    const account = value as Record<string, unknown>;
    return {
      name,
      host: requireString(account, name, 'host'),
      port: resolvePort(account, name),
      user: requireString(account, name, 'user'),
      password: requireString(account, name, 'password'),
    };
  });
}

/**
 * Refuse a credentials file that anyone but its owner can read.
 *
 * The file holds app passwords in cleartext, so loose permissions are a
 * startup error rather than a warning nobody reads.
 */
export function assertSecureMode(mode: number, path: string): void {
  const permissions = mode & 0o777;
  if (permissions & 0o077) {
    const octal = permissions.toString(8).padStart(3, '0');
    throw new Error(
      `${path} has permissions 0${octal}; it holds passwords and must be 0600 (chmod 600 ${path})`,
    );
  }
}

export function loadAccounts(env: Record<string, string | undefined>): Account[] {
  const path = env.MAILCOW_ACCOUNTS_FILE;
  if (!path) throw new Error('MAILCOW_ACCOUNTS_FILE is required');

  assertSecureMode(statSync(path).mode, path);

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`${path} is not valid JSON: ${(err as Error).message}`);
  }
  return parseAccounts(raw);
}
