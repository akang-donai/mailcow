// src/remote/app.ts
//
// Composition target for the Express application. Every dependency is
// injected via AppDeps -- this module never reads process.env and never
// opens a file, a socket, or a database itself, so it can be exercised
// end-to-end (Task 10) by handing it in-memory/fake collaborators.
import express from 'express';
import type { Express, Request } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { MailcowOAuthProvider } from './provider.ts';
import type { SqliteClientsStore, PendingStore, CredentialStore } from './store.ts';
import type { TenantRegistry } from './tenant-connections.ts';
import type { ImapVerifier } from './verify.ts';
import { renderConsent, handleConsent } from './consent.ts';
import { registerRemoteTools } from './tools.ts';

export type AppDeps = {
  provider: MailcowOAuthProvider;
  clientsStore: SqliteClientsStore;
  pending: PendingStore;
  credentials: CredentialStore;
  registry: TenantRegistry;
  verify: ImapVerifier;
  issuerUrl: URL;
  imapHost: string;
  imapPort: number;
};

// A framable OAuth consent screen is a clickjacking target: an attacker
// could overlay it and harvest a visitor's mailbox app password. Applied to
// both the GET (form) and POST (redirect/re-render) consent responses.
function setConsentSecurityHeaders(res: express.Response): void {
  res.set('X-Frame-Options', 'DENY');
  res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; style-src 'unsafe-inline'");
}

export function buildApp(deps: AppDeps): Express {
  const app = express();

  const consentDeps = {
    pending: deps.pending,
    credentials: deps.credentials,
    provider: deps.provider,
    clientsStore: deps.clientsStore,
    verify: deps.verify,
    imapHost: deps.imapHost,
    imapPort: deps.imapPort,
  };

  // Installs /authorize, /token, /register, /revoke and the .well-known
  // metadata endpoints. /authorize's validation (redirect_uri exact match,
  // S256 enforcement, client lookup) stays entirely inside the SDK; once it
  // passes, it calls provider.authorize(client, params, res), which main.ts
  // wires (via provider.setOnAuthorize) to redirect into the consent flow
  // built from consentDeps above.
  app.use(mcpAuthRouter({ provider: deps.provider, issuerUrl: deps.issuerUrl }));

  app.get('/consent', (req, res) => {
    const handle = typeof req.query.handle === 'string' ? req.query.handle : '';
    setConsentSecurityHeaders(res);
    res.type('html').send(renderConsent(handle));
  });

  app.post('/consent', express.urlencoded({ extended: false }), async (req, res) => {
    // handleConsent validates the shape of every field itself (a duplicated
    // form field, or a non-string value, is treated as absent/invalid) --
    // req.body is passed straight through with no duplicate checking here.
    const result = await handleConsent(consentDeps, req.body);
    setConsentSecurityHeaders(res);
    if ('redirectTo' in result) {
      res.redirect(result.redirectTo);
      return;
    }
    res.type('html').send(result.rerender);
  });

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(new URL('/mcp', deps.issuerUrl));

  app.post(
    '/mcp',
    requireBearerAuth({ verifier: deps.provider, resourceMetadataUrl }),
    express.json(),
    async (req: Request, res) => {
      // Isolation by construction: a fresh McpServer and a fresh stateless
      // transport per HTTP request, never hoisted to module scope, so no
      // state (registered tools, in-flight session, anything) is ever
      // shared between two different callers -- there is no session for a
      // session-confusion bug to confuse.
      const server = new McpServer({ name: 'mailcow-imap-remote', version: '0.1.0' });
      registerRemoteTools(server, { registry: deps.registry, credentials: deps.credentials });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

      res.on('close', () => {
        void transport.close();
        void server.close();
      });

      await server.connect(transport);
      // req.auth was populated by requireBearerAuth above; the transport
      // reads it to build the per-call authInfo the tools use to derive the
      // mailbox (see tools.ts subjectFromExtra). Without this the tools
      // would see no subject at all.
      await transport.handleRequest(req, res, req.body);
    },
  );

  return app;
}
