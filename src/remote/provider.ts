// src/remote/provider.ts
import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidGrantError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { randomToken } from './crypto.ts';
import type { SqliteClientsStore, CodeStore, TokenStore } from './store.ts';

type Ttls = { code: number; access: number; refresh: number };

export class MailcowOAuthProvider implements OAuthServerProvider {
  #clients: SqliteClientsStore;
  #codes: CodeStore;
  #tokens: TokenStore;
  #ttls: Ttls;
  #onAuthorize?: (client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) => void;

  constructor(deps: { clientsStore: SqliteClientsStore; codes: CodeStore; tokens: TokenStore; ttls: Ttls }) {
    this.#clients = deps.clientsStore;
    this.#codes = deps.codes;
    this.#tokens = deps.tokens;
    this.#ttls = deps.ttls;
  }

  get clientsStore(): OAuthRegisteredClientsStore { return this.#clients; }

  // The SDK's authorize handler validates the request (redirect_uri exact match,
  // S256 enforcement, client lookup) and then calls this. We need to collect the
  // mailbox app password via a consent page before a code can be issued, so this
  // redirects to that flow instead of issuing a code directly. The consent route
  // (Task 9) wires the real handler in via setOnAuthorize; if nothing has wired
  // one up yet, failing loudly is safer than silently doing nothing.
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (!this.#onAuthorize) throw new ServerError('authorize handler not configured');
    this.#onAuthorize(client, params, res);
  }

  setOnAuthorize(fn: (client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) => void): void {
    this.#onAuthorize = fn;
  }

  // Called by the consent handler once the mailbox owner has approved and their
  // app password has been verified. Generates and stores the authorization code
  // bound to the subject + PKCE challenge + redirect URI.
  completeAuthorization(input: {
    client: OAuthClientInformationFull;
    subject: string;
    params: { codeChallenge: string; redirectUri: string; scopes?: string[]; resource?: string };
  }): string {
    const code = randomToken();
    this.#codes.save(code, {
      clientId: input.client.client_id,
      subject: input.subject,
      codeChallenge: input.params.codeChallenge,
      redirectUri: input.params.redirectUri,
      resource: input.params.resource,
      ttlSec: this.#ttls.code,
    });
    return code;
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    // Peek without consuming: read the challenge for the SDK's PKCE gate.
    const peeked = this.#codes.peekChallenge(authorizationCode);
    if (!peeked) throw new InvalidGrantError('unknown or expired authorization code');
    return peeked;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<OAuthTokens> {
    const data = this.#codes.consume(authorizationCode);
    if (!data || data.clientId !== client.client_id) throw new InvalidGrantError('invalid authorization code');
    return this.#issuePair(client.client_id, data.subject, 'mail');
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
    const info = this.#tokens.verify(refreshToken);
    if (!info) {
      // If it exists but is consumed/revoked, this is a replay -> nuke the chain.
      if (this.#tokens.isConsumedOrRevoked(refreshToken)) {
        const stale = this.#tokens.subjectClientOf(refreshToken);
        if (stale) this.#tokens.revokeChainBySubjectClient(stale.subject, stale.clientId);
      }
      throw new InvalidGrantError('invalid refresh token');
    }
    if (info.clientId !== client.client_id) throw new InvalidGrantError('client mismatch');
    this.#tokens.markConsumed(refreshToken);
    return this.#issuePair(info.clientId, info.subject, (scopes ?? info.scope.split(' ')).join(' '), refreshToken);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const info = this.#tokens.verify(token);
    if (!info) throw new InvalidGrantError('invalid access token');
    return {
      token,
      clientId: info.clientId,
      scopes: info.scope.split(' '),
      expiresAt: info.expiresAt,
      extra: { subject: info.subject },
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: { token: string }): Promise<void> {
    this.#tokens.revoke(request.token);
  }

  #issuePair(clientId: string, subject: string, scope: string, rotatedFrom?: string): OAuthTokens {
    const access = this.#tokens.issue({ kind: 'access', clientId, subject, scope, ttlSec: this.#ttls.access });
    const refresh = this.#tokens.issue({ kind: 'refresh', clientId, subject, scope, ttlSec: this.#ttls.refresh, rotatedFrom });
    return { access_token: access, token_type: 'Bearer', expires_in: this.#ttls.access, refresh_token: refresh, scope };
  }
}
