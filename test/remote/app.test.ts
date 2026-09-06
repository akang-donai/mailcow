// test/remote/app.test.ts
//
// Targeted coverage for the two Important fixes from fix-round 1: the
// terminal error-handling middleware (no stack-trace leakage, structured
// OAuth errors preserved) and the 'trust proxy' setting. Full end-to-end
// OAuth-dance + /mcp coverage lives in Task 10; this file only exercises
// what those two fixes touch, driving buildApp with fetch against an
// ephemeral app.listen(0) the same way Task 10 does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore, PendingStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';
import { TenantRegistry } from '../../src/remote/tenant-connections.ts';
import { buildApp } from '../../src/remote/app.ts';
import { beginConsent } from '../../src/remote/consent.ts';

function fixture() {
  const db = openDb(':memory:');
  const clientsStore = new SqliteClientsStore(db);
  const codes = new CodeStore(db);
  const tokens = new TokenStore(db);
  const credentials = new CredentialStore(db, randomBytes(32));
  const pending = new PendingStore(db);
  const registry = new TenantRegistry({
    credentials,
    connector: () => ({ usable: true, connect: async () => {}, logout: async () => {} }),
  });
  const verify = async () => true;
  const provider = new MailcowOAuthProvider({ clientsStore, codes, tokens, ttls: { code: 60, access: 3600, refresh: 2592000 } });

  const consentDeps = { pending, credentials, provider, clientsStore, verify, imapHost: 'usagi', imapPort: 993 };
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

  const issuerUrl = new URL('https://example.test');
  const app = buildApp({ provider, clientsStore, pending, credentials, registry, verify, issuerUrl, imapHost: 'usagi', imapPort: 993 });
  return { app, clientsStore };
}

function listen(app: ReturnType<typeof buildApp>): Promise<import('node:http').Server> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function baseUrl(server: import('node:http').Server): string {
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

test('an unexpected error never leaks a stack trace to the caller, and is logged server-side instead', async () => {
  const { app } = fixture();
  const server = await listen(app);
  const originalError = console.error;
  const logged: unknown[][] = [];
  console.error = (...args: unknown[]) => { logged.push(args); };
  try {
    // Malformed JSON to the SDK's own /register route throws inside
    // express.json() before the SDK's internal try/catch ever runs -- this
    // is the exact path the reviewer used to demonstrate the leak.
    const res = await fetch(`${baseUrl(server)}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not valid json',
    });
    assert.equal(res.status, 500);
    const text = await res.text();
    // No stack-trace-shaped content, and no absolute path from this
    // checkout leaking into the response body.
    assert.doesNotMatch(text, /\bat .+:\d+:\d+\)?/);
    assert.ok(!text.includes(process.cwd()));
    const body = JSON.parse(text);
    assert.equal(body.stack, undefined);
    assert.ok(logged.length > 0, 'expected the real error to be logged server-side');
  } finally {
    console.error = originalError;
    server.close();
  }
});

test('a structured OAuth error (unsupported grant type) still returns its proper error code, not the generic body', async () => {
  const { app, clientsStore } = fixture();
  clientsStore.registerClient({
    client_id: 'c1',
    redirect_uris: ['https://claude.example/cb'],
    grant_types: ['authorization_code', 'refresh_token'],
  } as never);
  const server = await listen(app);
  try {
    const res = await fetch(`${baseUrl(server)}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'c1' }),
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, 'unsupported_grant_type');
    assert.equal(body.stack, undefined);
    // Distinguishes this from the generic fallback body the error
    // middleware produces for an unstructured error.
    assert.notEqual(body.error, 'server_error');
  } finally {
    server.close();
  }
});

test('the 401 challenge on /mcp advertises a resource_metadata URL that actually resolves, not a 404 (RFC 9728 discovery)', async () => {
  const { app } = fixture();
  const server = await listen(app);
  try {
    const res = await fetch(`${baseUrl(server)}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(res.status, 401);
    const wwwAuth = res.headers.get('www-authenticate');
    assert.ok(wwwAuth, 'expected a WWW-Authenticate header');
    // Parsed out of the header, not hardcoded -- hardcoding the path here
    // would let the mount path (mcpAuthRouter's resourceServerUrl) and the
    // advertised path (requireBearerAuth's resourceMetadataUrl) drift apart
    // again without this test ever noticing.
    const match = wwwAuth!.match(/resource_metadata="([^"]+)"/);
    assert.ok(match, `expected a resource_metadata challenge parameter in: ${wwwAuth}`);
    const advertised = new URL(match![1]);

    // fixture()'s issuerUrl is an unreachable placeholder domain, so the
    // advertised URL can't literally be fetched cross-network -- but Express
    // routes purely on method + path, never on the Host header, so fetching
    // the identical path against our own live server exercises exactly the
    // same routing decision the real client would make.
    const metaRes = await fetch(`${baseUrl(server)}${advertised.pathname}`);
    assert.equal(metaRes.status, 200, `resource_metadata URL path ${advertised.pathname} must resolve, not 404`);
    const body = (await metaRes.json()) as { resource?: string; authorization_servers?: string[] };
    assert.equal(body.resource, 'https://example.test/mcp');
    assert.ok(
      Array.isArray(body.authorization_servers) && body.authorization_servers.includes('https://example.test/'),
      `expected authorization_servers to include the issuer: ${JSON.stringify(body)}`,
    );
  } finally {
    server.close();
  }
});

test("trust proxy is set to 'loopback' (not true), so nginx's X-Forwarded-For is honoured but a direct caller can't spoof it", async () => {
  const { app } = fixture();
  assert.equal(app.get('trust proxy'), 'loopback');

  // Probe route added directly on the live instance (not part of app.ts)
  // purely to observe what req.ip resolves to for a real request arriving
  // from a loopback peer -- exactly nginx's position in production.
  app.get('/__test_probe_ip', (req, res) => {
    res.json({ ip: req.ip });
  });

  const server = await listen(app);
  try {
    const res = await fetch(`${baseUrl(server)}/__test_probe_ip`, {
      headers: { 'x-forwarded-for': '203.0.113.5' },
    });
    const body = await res.json();
    assert.equal(body.ip, '203.0.113.5');
  } finally {
    server.close();
  }
});
