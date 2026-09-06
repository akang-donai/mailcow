// src/remote/env.ts
//
// The only file that knows the shape of process.env -- main.ts calls this
// with process.env, tests call it with a plain object. Nothing here touches
// the filesystem or the network, so it can be exercised without a DB, a
// socket, or a real IMAP server.
const PLAINTEXT_IMAP_PORTS = new Set([110, 143]);

export type RemoteConfig = {
  issuerUrl: URL;
  port: number;
  dbPath: string;
  keyPath: string;
  imapHost: string;
  imapPort: number;
};

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function loadRemoteConfig(env: Record<string, string | undefined>): RemoteConfig {
  const issuerUrl = new URL(required(env, 'ISSUER_URL'));
  const keyPath = required(env, 'KEY_PATH');
  const dbPath = required(env, 'DB_PATH');
  const imapHost = required(env, 'MAILCOW_IMAP_HOST');

  const port = env.PORT ? Number(env.PORT) : 8787;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid PORT: ${env.PORT}`);
  }

  const imapPort = env.MAILCOW_IMAP_PORT ? Number(env.MAILCOW_IMAP_PORT) : 993;
  if (!Number.isInteger(imapPort) || imapPort < 1 || imapPort > 65535) {
    throw new Error(`invalid MAILCOW_IMAP_PORT: ${env.MAILCOW_IMAP_PORT}`);
  }
  // Mailbox app passwords are the credential this whole system stores and
  // replays; a cleartext IMAP connection would put every one of them on the
  // wire in the open. Implicit TLS (993) or STARTTLS-only alternates are
  // fine, but the two well-known plaintext ports are refused outright.
  if (PLAINTEXT_IMAP_PORTS.has(imapPort)) {
    throw new Error(`MAILCOW_IMAP_PORT ${imapPort} is a cleartext port; implicit TLS is required`);
  }

  return { issuerUrl, port, dbPath, keyPath, imapHost, imapPort };
}
