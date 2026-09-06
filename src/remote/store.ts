// src/remote/store.ts
import type { DatabaseSync } from 'node:sqlite';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { hashToken, randomToken, encryptSecret, decryptSecret } from './crypto.ts';

const nowSec = () => Math.floor(Date.now() / 1000);

export class SqliteClientsStore implements OAuthRegisteredClientsStore {
  #db: DatabaseSync;
  constructor(db: DatabaseSync) { this.#db = db; }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row: any = this.#db.prepare('select * from oauth_clients where client_id=?').get(clientId);
    if (!row) return undefined;
    return {
      client_id: row.client_id,
      client_name: row.client_name ?? undefined,
      redirect_uris: JSON.parse(row.redirect_uris),
      grant_types: row.grant_types ? row.grant_types.split(' ') : undefined,
      scope: row.scope ?? undefined,
      client_id_issued_at: row.created_at,
      client_secret: row.client_secret ?? undefined,
      client_secret_expires_at: row.client_secret_expires_at ?? undefined,
    } as OAuthClientInformationFull;
  }

  registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
    this.#db.prepare(
      'insert into oauth_clients(client_id,client_name,redirect_uris,grant_types,scope,created_at,client_secret,client_secret_expires_at) values (?,?,?,?,?,?,?,?)'
    ).run(
      client.client_id,
      client.client_name ?? null,
      JSON.stringify(client.redirect_uris ?? []),
      (client.grant_types ?? ['authorization_code', 'refresh_token']).join(' '),
      client.scope ?? null,
      client.client_id_issued_at ?? nowSec(),
      client.client_secret ?? null,
      client.client_secret_expires_at ?? null,
    );
    return client;
  }
}

type CodeData = { clientId: string; subject: string; codeChallenge: string; redirectUri: string; resource: string | undefined };

export class CodeStore {
  #db: DatabaseSync;
  constructor(db: DatabaseSync) { this.#db = db; }

  save(code: string, d: CodeData & { ttlSec: number }): void {
    this.#db.prepare(
      'insert into authorization_codes(code_hash,client_id,subject,code_challenge,redirect_uri,resource,expires_at) values (?,?,?,?,?,?,?)'
    ).run(hashToken(code), d.clientId, d.subject, d.codeChallenge, d.redirectUri, d.resource ?? null, nowSec() + d.ttlSec);
  }

  consume(code: string): CodeData | null {
    const h = hashToken(code);
    const row: any = this.#db.prepare('select * from authorization_codes where code_hash=?').get(h);
    if (!row || row.consumed_at || row.expires_at < nowSec()) return null;
    const res = this.#db.prepare('update authorization_codes set consumed_at=? where code_hash=? and consumed_at is null').run(nowSec(), h);
    if (res.changes !== 1) return null; // lost the race
    return { clientId: row.client_id, subject: row.subject, codeChallenge: row.code_challenge, redirectUri: row.redirect_uri, resource: row.resource ?? undefined };
  }

  // Reads the stored PKCE challenge without consuming the code. The SDK's token
  // handler calls this to verify the code_verifier BEFORE exchanging the code, so
  // this must not mutate consumed_at, and must apply the same expiry/consumed gate
  // as consume() so a dead code never leaks its challenge.
  peekChallenge(code: string): string | null {
    const h = hashToken(code);
    const row: any = this.#db.prepare('select * from authorization_codes where code_hash=?').get(h);
    if (!row || row.consumed_at != null || row.expires_at < nowSec()) return null;
    return row.code_challenge;
  }
}

export class TokenStore {
  #db: DatabaseSync;
  constructor(db: DatabaseSync) { this.#db = db; }

  issue(d: { kind: 'access' | 'refresh'; clientId: string; subject: string; scope: string; ttlSec: number; rotatedFrom?: string }): string {
    const token = randomToken();
    this.#db.prepare(
      'insert into tokens(token_hash,kind,client_id,subject,scope,expires_at,rotated_from) values (?,?,?,?,?,?,?)'
    ).run(hashToken(token), d.kind, d.clientId, d.subject, d.scope, nowSec() + d.ttlSec, d.rotatedFrom ? hashToken(d.rotatedFrom) : null);
    return token;
  }

  // expectedKind, when given, rejects a token whose stored kind differs -- an
  // access token must never verify as a refresh token or vice versa (see
  // exchangeRefreshToken / verifyAccessToken in provider.ts, which always pass it).
  verify(token: string, expectedKind?: 'access' | 'refresh'): { clientId: string; subject: string; scope: string; expiresAt: number } | null {
    const row: any = this.#db.prepare('select * from tokens where token_hash=?').get(hashToken(token));
    if (!row || row.revoked_at || row.consumed_at != null || row.expires_at < nowSec()) return null;
    if (expectedKind && row.kind !== expectedKind) return null;
    return { clientId: row.client_id, subject: row.subject, scope: row.scope, expiresAt: row.expires_at };
  }

  isConsumedOrRevoked(token: string): boolean {
    const row: any = this.#db.prepare('select revoked_at,consumed_at from tokens where token_hash=?').get(hashToken(token));
    if (!row) return false;
    return row.revoked_at != null || row.consumed_at != null;
  }

  // Conditional on consumed_at still being NULL, mirroring CodeStore.consume's
  // race guard: under the shared-SQLite-file deployment this project assumes, two
  // workers could otherwise both "successfully" consume the same live refresh
  // token, and reuse detection would never fire. Returns whether THIS call won.
  markConsumed(token: string): boolean {
    const res = this.#db.prepare('update tokens set consumed_at=? where token_hash=? and consumed_at is null').run(nowSec(), hashToken(token));
    return res.changes === 1;
  }

  revoke(token: string): void {
    this.#db.prepare('update tokens set revoked_at=? where token_hash=?').run(nowSec(), hashToken(token));
  }

  revokeChainBySubjectClient(subject: string, clientId: string): void {
    this.#db.prepare('update tokens set revoked_at=? where subject=? and client_id=? and revoked_at is null').run(nowSec(), subject, clientId);
  }

  // Every live token for a mailbox, across every client. Used when a subject
  // completes a fresh consent: that is the mailbox owner re-stating who may
  // read their mail, so anything issued earlier -- including a token some
  // other client holds -- stops working. revokeChainBySubjectClient is the
  // narrower theft-response tool and is deliberately kept separate.
  revokeAllBySubject(subject: string): void {
    this.#db.prepare('update tokens set revoked_at=? where subject=? and revoked_at is null').run(nowSec(), subject);
  }

  // Resolves subject+client+kind for a token hash even when it is consumed or
  // revoked (unlike verify(), which treats those as absent). This is how a
  // replayed refresh token is traced back to the chain that must be revoked, and
  // how revokeToken() learns whether a presented token is a refresh token (whose
  // whole grant must die) or a lone access token -- if this returned null for a
  // consumed/revoked token, theft detection would silently fail.
  subjectClientOf(token: string): { subject: string; clientId: string; kind: 'access' | 'refresh' } | null {
    const row: any = this.#db.prepare('select subject,client_id,kind from tokens where token_hash=?').get(hashToken(token));
    if (!row) return null;
    return { subject: row.subject, clientId: row.client_id, kind: row.kind };
  }
}

export class CredentialStore {
  #db: DatabaseSync;
  #key: Buffer;
  constructor(db: DatabaseSync, key: Buffer) { this.#db = db; this.#key = key; }

  put(subject: string, host: string, port: number, appPassword: string): void {
    const packed = encryptSecret(appPassword, this.#key, subject);
    this.#db.prepare(
      `insert into credentials(subject,host,port,ciphertext,nonce,verified_at,invalid_since) values (?,?,?,?,?,?,null)
       on conflict(subject) do update set host=excluded.host,port=excluded.port,ciphertext=excluded.ciphertext,verified_at=excluded.verified_at,invalid_since=null`
    ).run(subject, host, port, packed, '', nowSec());
  }

  get(subject: string): { host: string; port: number; appPassword: string } | null {
    const row: any = this.#db.prepare('select * from credentials where subject=?').get(subject);
    if (!row || row.invalid_since != null) return null;
    return { host: row.host, port: row.port, appPassword: decryptSecret(row.ciphertext, this.#key, subject) };
  }

  markInvalid(subject: string): void {
    this.#db.prepare('update credentials set invalid_since=? where subject=?').run(nowSec(), subject);
  }

  touch(subject: string): void {
    this.#db.prepare('update credentials set last_used_at=? where subject=?').run(nowSec(), subject);
  }
}

type PendingData = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  resource?: string;
  scopes?: string[];
};

// Backs the consent handoff between the SDK's /authorize route and the
// mailbox-credential form at /consent. The handle is a bearer value (whoever
// holds it can complete the pending authorization), so it is stored hashed
// -- exactly like an authorization code or token -- never in the clear.
export class PendingStore {
  #db: DatabaseSync;
  constructor(db: DatabaseSync) { this.#db = db; }

  // browserToken is the second half of the consent binding (see
  // consent.ts): the handle travels in a URL, this one only ever in a
  // path-scoped HttpOnly cookie. Stored hashed for the same reason the
  // handle is -- both are bearer values.
  save(handle: string, d: PendingData & { browserToken: string; ttlSec: number }): void {
    this.#db.prepare(
      'insert into pending_authorizations(handle_hash,client_id,redirect_uri,code_challenge,state,resource,scopes,expires_at,browser_token_hash) values (?,?,?,?,?,?,?,?,?)'
    ).run(hashToken(handle), d.clientId, d.redirectUri, d.codeChallenge, d.state ?? null, d.resource ?? null, (d.scopes ?? []).join(' '), nowSec() + d.ttlSec, hashToken(d.browserToken));
  }

  get(handle: string): (PendingData & { scopes: string[]; browserTokenHash: string | null }) | null {
    const row: any = this.#db.prepare('select * from pending_authorizations where handle_hash=?').get(hashToken(handle));
    if (!row || row.expires_at < nowSec()) return null;
    return {
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      state: row.state ?? undefined,
      resource: row.resource ?? undefined,
      scopes: row.scopes ? row.scopes.split(' ') : [],
      // Null only for a row written before the binding existed. The caller
      // treats that as "no match", which fails closed.
      browserTokenHash: row.browser_token_hash ?? null,
    };
  }

  delete(handle: string): void {
    this.#db.prepare('delete from pending_authorizations where handle_hash=?').run(hashToken(handle));
  }
}
