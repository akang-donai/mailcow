// src/remote/main.ts
//
// Composition root. This is the ONLY file in src/remote that touches
// process.env, the filesystem, or the network -- everything else (env.ts,
// app.ts, and every Task 1-8 module) takes its dependencies as parameters
// so it can be constructed and tested without any of those.
import { readFileSync } from 'node:fs';
import { ImapFlow } from 'imapflow';
import { loadRemoteConfig, type RemoteConfig } from './env.ts';
import { openDb } from './db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore, PendingStore } from './store.ts';
import { MailcowOAuthProvider } from './provider.ts';
import { makeImapVerifier } from './verify.ts';
import { TenantRegistry } from './tenant-connections.ts';
import { buildApp } from './app.ts';
import { beginConsent, type ConsentDeps } from './consent.ts';

// Fail closed and say why, without a raw stack trace obscuring the actual
// misconfiguration (a missing env var, an unreadable key file, a bad key
// length). Anything reaching main() past this point is trusted to be sane.
function fail(message: string): never {
  console.error(`mailcp remote: ${message}`);
  process.exit(1);
}

function loadConfig(): RemoteConfig {
  try {
    return loadRemoteConfig(process.env);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
}

function loadKey(keyPath: string): Buffer {
  let key: Buffer;
  try {
    key = readFileSync(keyPath);
  } catch (err) {
    fail(`could not read KEY_PATH (${keyPath}): ${err instanceof Error ? err.message : String(err)}`);
  }
  // A short key would silently weaken every credential the CredentialStore
  // encrypts with it (AES-256-GCM needs the full 32 bytes) -- reject
  // anything else outright rather than accept a weaker-than-intended key.
  if (key.length !== 32) {
    fail(`${keyPath} must contain exactly 32 bytes (256-bit key), got ${key.length}`);
  }
  return key;
}

function main(): void {
  const cfg = loadConfig();
  const key = loadKey(cfg.keyPath);

  const db = openDb(cfg.dbPath);
  const clientsStore = new SqliteClientsStore(db);
  const codes = new CodeStore(db);
  const tokens = new TokenStore(db);
  const credentials = new CredentialStore(db, key);
  const pending = new PendingStore(db);

  const imapFactory = (host: string, port: number, user: string, pass: string): ImapFlow =>
    new ImapFlow({ host, port, secure: true, auth: { user, pass }, logger: false });

  const verify = makeImapVerifier(imapFactory);
  const registry = new TenantRegistry({ credentials, connector: imapFactory });

  const provider = new MailcowOAuthProvider({
    clientsStore,
    codes,
    tokens,
    ttls: { code: 60, access: 3600, refresh: 2592000 },
  });

  const consentDeps: ConsentDeps = {
    pending,
    credentials,
    provider,
    clientsStore,
    verify,
    imapHost: cfg.imapHost,
    imapPort: cfg.imapPort,
  };

  // The SDK's /authorize handler validates the request (redirect_uri exact
  // match, S256 enforcement, client lookup) and then calls
  // provider.authorize(client, params, res); MailcowOAuthProvider forwards
  // that straight to whatever is wired in here. We need the mailbox owner
  // to prove an app password before a code is ever issued, so this sends
  // them into the consent flow instead of minting one directly.
  provider.setOnAuthorize((client, params, res) => {
    res.redirect(
      beginConsent(consentDeps, {
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state,
        resource: params.resource?.href,
        scopes: params.scopes,
      }),
    );
  });

  const app = buildApp({
    provider,
    clientsStore,
    pending,
    credentials,
    registry,
    verify,
    issuerUrl: cfg.issuerUrl,
    imapHost: cfg.imapHost,
    imapPort: cfg.imapPort,
  });

  // Loopback only. nginx terminates TLS and applies rate limiting in front
  // of this process; binding to anything wider (e.g. 0.0.0.0) would let
  // every other host on the LAN reach the OAuth and MCP endpoints directly,
  // bypassing TLS, mailcow's rate limits, and the security headers set in
  // app.ts.
  app.listen(cfg.port, '127.0.0.1', () => {
    console.log(`mailcp remote listening on 127.0.0.1:${cfg.port}`);
  });
}

main();
