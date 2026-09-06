// src/remote/provider.ts
import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidGrantError, InvalidScopeError, InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { randomToken } from './crypto.ts';
import type { SqliteClientsStore, CodeStore, TokenStore } from './store.ts';

type Ttls = { code: number; access: number; refresh: number };

export class MailcowOAuthProvider implements OAuthServerProvider {
  #clients: SqliteClientsStore;
  #codes: CodeStore;
  #tokens: TokenStore;
  #ttls: Ttls;
  #onAuthorize?: (client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) => void | Promise<void>;

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
    // Awaited so a rejecting async handler surfaces through this method's promise
    // instead of becoming a floating, unhandled rejection that bypasses the SDK's
    // error handling.
    await this.#onAuthorize(client, params, res);
  }

  setOnAuthorize(fn: (client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) => void | Promise<void>): void {
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

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    _resource?: URL,
  ): Promise<OAuthTokens> {
    const data = this.#codes.consume(authorizationCode);
    if (!data || data.clientId !== client.client_id) throw new InvalidGrantError('invalid authorization code');
    // RFC 6749 4.1.3: the redirect_uri presented at the token endpoint must match
    // the one bound to the code at authorization time. The SDK passes undefined
    // when the client omitted it (e.g. it was the client's only registered URI);
    // that is not evidence of tampering, so only a *mismatched* value is rejected.
    if (redirectUri !== undefined && redirectUri !== data.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the one used to obtain the authorization code');
    }
    return this.#issuePair(client.client_id, data.subject, 'mail');
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
    // Kind is load-bearing: without it, a leaked access token redeemed here would
    // mint a fresh, indefinitely-renewable pair (and never touch the chain a real
    // client would replay), and the reuse-detection branch below would trace a
    // token that was never a refresh token in the first place.
    const info = this.#tokens.verify(refreshToken, 'refresh');
    if (!info) {
      // Exists (of *some* kind) but failed verify -> could be expired, wrong kind,
      // or -- the case that matters -- already consumed/revoked, meaning two
      // parties hold it and one is a thief. Only a genuine refresh-token replay
      // revokes the chain; a wrong-kind token (e.g. an access token) never reaches
      // isConsumedOrRevoked()===true here in the ordinary case, since access
      // tokens are never consumed and are only revoked as part of a chain that's
      // already dead (a harmless no-op re-revoke).
      if (this.#tokens.isConsumedOrRevoked(refreshToken)) {
        const stale = this.#tokens.subjectClientOf(refreshToken);
        if (stale) this.#tokens.revokeChainBySubjectClient(stale.subject, stale.clientId);
      }
      throw new InvalidGrantError('invalid refresh token');
    }
    if (info.clientId !== client.client_id) {
      // A LIVE, valid refresh token presented by the wrong client is stronger
      // evidence of theft than a spent one: another authenticated party currently
      // holds a working credential for this subject. Kill the real owner's chain
      // too rather than merely rejecting this one request.
      this.#tokens.revokeChainBySubjectClient(info.subject, info.clientId);
      throw new InvalidGrantError('refresh token was not issued to this client');
    }

    const grantedScopes = info.scope.split(' ');
    let nextScope = info.scope;
    if (scopes) {
      const notGranted = scopes.filter((s) => !grantedScopes.includes(s));
      if (notGranted.length > 0) {
        throw new InvalidScopeError(`scope(s) exceed what was granted: ${notGranted.join(' ')}`);
      }
      nextScope = scopes.join(' ');
    }

    // Conditional consume: if this call loses the race (another request already
    // consumed this exact token), that is itself a replay -- treat it exactly
    // like the isConsumedOrRevoked() branch above rather than silently minting a
    // second valid pair from the same single-use refresh token.
    const won = this.#tokens.markConsumed(refreshToken);
    if (!won) {
      const stale = this.#tokens.subjectClientOf(refreshToken);
      if (stale) this.#tokens.revokeChainBySubjectClient(stale.subject, stale.clientId);
      throw new InvalidGrantError('invalid refresh token');
    }
    return this.#issuePair(info.clientId, info.subject, nextScope, refreshToken);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    // expectedKind 'access': a refresh token must never authenticate an MCP
    // request just because it happens to verify (it would otherwise pass with a
    // 30-day expiry instead of the intended 1-hour access-token lifetime).
    const info = this.#tokens.verify(token, 'access');
    // InvalidTokenError, not InvalidGrantError: the SDK's bearerAuth middleware
    // special-cases InvalidTokenError to respond 401 + WWW-Authenticate (carrying
    // the RFC 9728 resource_metadata discovery hint), which is what drives
    // Claude's re-auth flow. Any other error class falls through to a bare 400
    // with no challenge header, and the connector just looks broken.
    if (!info) throw new InvalidTokenError('invalid access token');
    return {
      token,
      clientId: info.clientId,
      scopes: info.scope.split(' '),
      expiresAt: info.expiresAt,
      extra: { subject: info.subject },
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: { token: string }): Promise<void> {
    // RFC 7009 2.1: revoking a refresh token SHOULD invalidate the entire grant,
    // not just that one token. An access token, by contrast, is revoked alone.
    const meta = this.#tokens.subjectClientOf(request.token);
    if (meta?.kind === 'refresh') {
      this.#tokens.revokeChainBySubjectClient(meta.subject, meta.clientId);
    } else {
      this.#tokens.revoke(request.token);
    }
  }

  #issuePair(clientId: string, subject: string, scope: string, rotatedFrom?: string): OAuthTokens {
    const access = this.#tokens.issue({ kind: 'access', clientId, subject, scope, ttlSec: this.#ttls.access });
    const refresh = this.#tokens.issue({ kind: 'refresh', clientId, subject, scope, ttlSec: this.#ttls.refresh, rotatedFrom });
    return { access_token: access, token_type: 'Bearer', expires_in: this.#ttls.access, refresh_token: refresh, scope };
  }
}
