export type Config = {
  host: string;
  port: number;
  user: string;
  password: string;
};

/** Ports that speak cleartext IMAP/POP3. This server only does implicit TLS. */
const PLAINTEXT_PORTS = new Set([110, 143]);

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function loadConfig(env: Record<string, string | undefined>): Config {
  const host = required(env, 'MAILCOW_IMAP_HOST');
  const user = required(env, 'MAILCOW_IMAP_USER');
  const password = required(env, 'MAILCOW_IMAP_PASSWORD');

  const port = env.MAILCOW_IMAP_PORT ? Number(env.MAILCOW_IMAP_PORT) : 993;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`MAILCOW_IMAP_PORT is not a valid port: ${env.MAILCOW_IMAP_PORT}`);
  }
  if (PLAINTEXT_PORTS.has(port)) {
    throw new Error(`port ${port} is cleartext; this server requires implicit TLS (993)`);
  }

  return { host, port, user, password };
}
