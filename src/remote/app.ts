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
import type { SqliteClientsStore, PendingStore, CredentialStore, TokenStore } from './store.ts';
import type { TenantRegistry } from './tenant-connections.ts';
import type { ImapVerifier } from './verify.ts';
import type { SmtpProbe } from '../smtp-check.ts';
import { renderConsent, handleConsent, consentView, readConsentCookie } from './consent.ts';
import { registerRemoteTools } from './tools.ts';

export type AppDeps = {
  provider: MailcowOAuthProvider;
  clientsStore: SqliteClientsStore;
  pending: PendingStore;
  credentials: CredentialStore;
  tokens: TokenStore;
  registry: TenantRegistry;
  verify: ImapVerifier;
  issuerUrl: URL;
  imapHost: string;
  imapPort: number;
  smtpProbe: SmtpProbe;
  smtpHost: string;
  smtpPort: number;
};

// A framable OAuth consent screen is a clickjacking target: an attacker
// could overlay it and harvest a visitor's mailbox app password. Applied to
// both the GET (form) and POST (redirect/re-render) consent responses.
//
// no-store covers both directions: the GET carries the pending handle and,
// after a failed attempt, the mailbox the visitor typed; the POST's 302
// carries a live authorization code in its Location header. Neither belongs
// in a shared cache, a proxy, or the browser's back/forward cache. The SDK
// sets this itself on /authorize and /token -- these two routes are ours,
// and were the gap.
function setConsentSecurityHeaders(res: express.Response): void {
  res.set('X-Frame-Options', 'DENY');
  res.set('Content-Security-Policy', "default-src 'none'; form-action 'self'; style-src 'unsafe-inline'");
  res.set('Cache-Control', 'no-store');
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

  // Exactly one hop -- nginx -- is trusted. Without this the SDK's built-in
  // rate limiters on /register (20/hr), /token (50/15min) and /authorize
  // (100/15min) key every tenant's traffic to a single address, so one
  // caller can block all token refreshes domain-wide for 15 minutes and all
  // new enrolments for an hour.
  //
  // NOT 'loopback', which is inert under Docker: the socket peer there is
  // the bridge gateway (172.x.0.1), never 127.0.0.1, so X-Forwarded-For was
  // ignored and req.ip was the gateway for everyone -- one shared bucket
  // for the whole internet. NOT `true` either, which trusts the entire
  // chain and lets a caller prepend whatever it likes.
  //
  // `1` means "skip the socket peer, take the next address from the right
  // of X-Forwarded-For". nginx sets that header with
  // $proxy_add_x_forwarded_for, which APPENDS the real peer, so the
  // rightmost entry is the address nginx observed. A client that sends its
  // own X-Forwarded-For only prepends to a list whose last element nginx
  // still writes.
  //
  // What this does not do: distinguish nginx from any other local process.
  // Express sees a TCP connection, not an identity. Remote clients cannot
  // reach 8787 (it is published on the host's loopback only), but any
  // process already running on merbabu can connect to it directly and set
  // this header to anything. That is not a new exposure -- a compromise of
  // the shared host is already documented as catastrophic for this service
  // in deploy/README.md, since the AES key and the database are readable
  // off disk at that point.
  app.set('trust proxy', 1);

  const consentDeps = {
    pending: deps.pending,
    credentials: deps.credentials,
    provider: deps.provider,
    clientsStore: deps.clientsStore,
    tokens: deps.tokens,
    verify: deps.verify,
    imapHost: deps.imapHost,
    imapPort: deps.imapPort,
    smtpProbe: deps.smtpProbe,
    smtpHost: deps.smtpHost,
    smtpPort: deps.smtpPort,
  };

  // This single value decides BOTH where the SDK mounts the
  // .well-known/oauth-protected-resource document (via resourceServerUrl
  // below -- its path becomes the mount's suffix) AND what URL the 401
  // WWW-Authenticate challenge on /mcp actually points a client at (via
  // resourceMetadataUrl further down). Those two must never be computed
  // independently: they previously were (one from issuerUrl, one from
  // `/mcp` off issuerUrl), so the document mounted at the issuer root while
  // the challenge advertised `<issuer>/mcp` -- a 404 on the exact discovery
  // request an unauthenticated Claude connector makes first.
  const resourceServerUrl = new URL('/mcp', deps.issuerUrl);

  // Installs /authorize, /token, /register, /revoke and the .well-known
  // metadata endpoints (including the protected-resource document, mounted
  // under resourceServerUrl's path so it lines up with resourceMetadataUrl
  // below). /authorize's validation (redirect_uri exact match, S256
  // enforcement, client lookup) stays entirely inside the SDK; once it
  // passes, it calls provider.authorize(client, params, res), which main.ts
  // wires (via provider.setOnAuthorize) to redirect into the consent flow
  // built from consentDeps above.
  app.use(
    mcpAuthRouter({
      provider: deps.provider,
      issuerUrl: deps.issuerUrl,
      resourceServerUrl,
      resourceName: 'mailcow IMAP (read-only)',
    }),
  );

  app.get('/consent', (req, res) => {
    const handle = typeof req.query.handle === 'string' ? req.query.handle : '';
    setConsentSecurityHeaders(res);
    // consentView resolves the requesting client's name and the origin the
    // browser will be sent to from the pending row, so the page can say who
    // is actually asking instead of asserting a vendor name.
    res.type('html').send(renderConsent(consentView(consentDeps, handle)));
  });

  app.post('/consent', express.urlencoded({ extended: false }), async (req, res) => {
    // handleConsent validates the shape of every field itself (a duplicated
    // form field, or a non-string value, is treated as absent/invalid) --
    // req.body is passed straight through with no duplicate checking here.
    // The cookie is read from the raw header rather than via cookie-parser:
    // one path-scoped cookie does not justify another dependency in an
    // internet-facing process.
    const result = await handleConsent(consentDeps, req.body, readConsentCookie(req.headers.cookie), res);
    setConsentSecurityHeaders(res);
    if ('redirectTo' in result) {
      res.redirect(result.redirectTo);
      return;
    }
    res.type('html').send(result.rerender);
  });

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);

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
