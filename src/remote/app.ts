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
import { OAuthError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
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

// Terminal error handler -- Express identifies this as error-handling
// middleware purely by its four declared parameters (the unused `next` is
// required for that; dropping it turns this into an ordinary, never-called
// middleware). Mounted last, after every route.
//
// The SDK's own OAuth handlers (register/token/authorize) already catch and
// format their own errors internally and reply directly -- they never call
// next(err) for those, so a structured OAuthError essentially never reaches
// this handler in practice. It only activates for what those internal
// try/catches can't see: a body-parser failure upstream of a route (e.g.
// malformed JSON POSTed to /register throws inside express.json(), before
// the SDK's handler ever runs), or an unexpected exception thrown by our
// own route logic. Express's default error path would otherwise embed
// `err.stack` -- absolute filesystem paths, dependency internals -- in the
// HTTP response to a completely unauthenticated caller.
function errorHandler(err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction): void {
  // A streamed/partially-sent response can't be rewritten; Express's own
  // default handler is the correct place to close the connection out.
  if (res.headersSent) {
    next(err);
    return;
  }
  // Preserve the SDK's own status/body convention for a structured OAuth
  // error, in the rare case one does reach this far -- clients parse
  // {"error": "...", "error_description": "..."} and depend on the code.
  if (err instanceof OAuthError) {
    const status = err instanceof ServerError ? 500 : 400;
    res.status(status).json(err.toResponseObject());
    return;
  }
  // Anything else is unexpected: the real error (and its stack) goes to
  // the server log only, never into the response body.
  console.error('mailcp remote: unhandled request error', err);
  res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
}

export function buildApp(deps: AppDeps): Express {
  const app = express();

  // Standard hardening: don't advertise the framework in responses.
  app.disable('x-powered-by');

  // nginx terminates TLS on this same host and proxies to loopback, so
  // every request's TCP peer is 127.0.0.1 -- without this, the SDK's
  // built-in rate limiters on /register, /authorize and /token key every
  // tenant's traffic to that single address, so one noisy user throttles
  // the entire mail domain. 'loopback' (never `true`) trusts only
  // 127.0.0.1/::1 as a forwarding proxy -- exactly and only nginx -- so a
  // client that reached this process directly still can't spoof
  // X-Forwarded-For to evade the limiter.
  app.set('trust proxy', 'loopback');

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

  // Must be registered after every route -- Express only reaches
  // error-handling middleware that comes after the throw site in the stack.
  app.use(errorHandler);

  return app;
}
