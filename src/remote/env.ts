// src/remote/env.ts
//
// The only file that knows the shape of process.env -- main.ts calls this
// with process.env, tests call it with a plain object. Nothing here touches
// the filesystem or the network, so it can be exercised without a DB, a
// socket, or a real IMAP server.
import { isIP } from 'node:net';

const PLAINTEXT_IMAP_PORTS = new Set([110, 143]);

export type RemoteConfig = {
  issuerUrl: URL;
  port: number;
  bindAddr: string;
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

  // Which interface the HTTP listener binds to, NOT a network-exposure
  // control on its own -- see deploy/README.md "Bind address vs published
  // port". Bare-metal use defaults to loopback so an un-configured process
  // is never reachable off-box; under Docker this must be 0.0.0.0, because
  // a published port DNATs to the container's *bridge* address and a
  // listener on the container's own loopback is unreachable from it. The
  // host-side isolation there comes from the `127.0.0.1:8787:8787` port
  // mapping in deploy/docker-compose.yml, not from this value.
  //
  // An IP literal is required rather than a hostname: a hostname would be
  // resolved by listen() at startup, so a DNS change (or a hosts-file entry
  // on a shared box) could silently move the listener onto a wider
  // interface than the operator intended.
  const bindAddr = env.BIND_ADDR ?? '127.0.0.1';
  if (isIP(bindAddr) === 0) {
    throw new Error(`invalid BIND_ADDR: ${JSON.stringify(env.BIND_ADDR)} (expected an IPv4 or IPv6 literal, e.g. 127.0.0.1 or 0.0.0.0)`);
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

  return { issuerUrl, port, bindAddr, dbPath, keyPath, imapHost, imapPort };
}
