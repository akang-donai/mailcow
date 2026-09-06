// test/remote/integration.test.ts
//
// End-to-end integration and tenant-isolation suite (Task 10). Drives the
// real Express app -- discovery, dynamic client registration, /authorize,
// /consent, /token, and /mcp -- over real HTTP against an ephemeral
// app.listen(0), exactly the way a real Claude connector would. The IMAP
// layer is always fake (no network); the two enrolled subjects have visibly
// different folder lists and messages so any crossover is unmistakable.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { openDb } from '../../src/remote/db.ts';
import { SqliteClientsStore, CodeStore, TokenStore, CredentialStore, PendingStore } from '../../src/remote/store.ts';
import { MailcowOAuthProvider } from '../../src/remote/provider.ts';
import { TenantRegistry } from '../../src/remote/tenant-connections.ts';
import { buildApp } from '../../src/remote/app.ts';
import { beginConsent } from '../../src/remote/consent.ts';

// ---------------------------------------------------------------------------
// Fake mailboxes. Two subjects, two entirely distinct sets of folders,
// senders, subjects and attachment names -- any test that leaks content from
// the wrong mailbox will show it as a literal, unmissable substring mismatch.
// ---------------------------------------------------------------------------

function rawMessage(headers: Record<string, string>, boundary: string, body: string, attachmentName: string): Buffer {
  return Buffer.from(
    [
      ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain',
      '',
      body,
      `--${boundary}`,
      'Content-Type: application/pdf',
      `Content-Disposition: attachment; filename="${attachmentName}"`,
      '',
      'PDFDATA',
      `--${boundary}--`,
      '',
    ].join('\r\n'),
    'utf8',
  );
}

type FakeMessage = {
  uid: number;
  envelope: { date: Date; subject: string; from: Array<{ address: string }> };
  source: Buffer;
};

type FakeMailbox = { folders: string[]; messages: FakeMessage[] };

const MAILBOXES: Record<string, FakeMailbox> = {
  'harry@x': {
    folders: ['INBOX', 'Harry-Sent'],
    messages: [
      {
        uid: 101,
        envelope: { date: new Date('2026-01-05T00:00:00Z'), subject: 'Harry Secret Plan', from: [{ address: 'ally@harry.example' }] },
        source: rawMessage(
          { From: 'ally@harry.example', Subject: 'Harry Secret Plan', Date: 'Mon, 05 Jan 2026 00:00:00 +0000' },
          'HARRY-BOUNDARY',
          'Meet at the burrow at midnight.',
          'harry-invoice.pdf',
        ),
      },
    ],
  },
  'dea@x': {
    folders: ['INBOX', 'Dea-Archive'],
    messages: [
      {
        uid: 201,
        envelope: { date: new Date('2026-02-09T00:00:00Z'), subject: 'Dea Confidential Memo', from: [{ address: 'boss@dea.example' }] },
        source: rawMessage(
          { From: 'boss@dea.example', Subject: 'Dea Confidential Memo', Date: 'Mon, 09 Feb 2026 00:00:00 +0000' },
          'DEA-BOUNDARY',
          'Quarterly numbers are attached.',
          'dea-invoice.pdf',
        ),
      },
    ],
  },
};

// Markers unique enough to a single mailbox that their presence in a
// response is unambiguous proof of which mailbox was actually read.
const HARRY_MARKERS = ['Harry-Sent', 'Harry Secret Plan', 'ally@harry.example', 'harry-invoice.pdf', 'burrow'];
const DEA_MARKERS = ['Dea-Archive', 'Dea Confidential Memo', 'boss@dea.example', 'dea-invoice.pdf', 'Quarterly numbers'];

// The connection returned is selected ENTIRELY by `user` (the credential
// looked up for the authenticated token's subject) -- the query/fetch calls
// below never look at their arguments to decide which mailbox to answer
// from. This is what makes the "hostile payload" test meaningful: even a
// query built entirely from attacker-supplied tool arguments can't change
// which mailbox this factory reads from, because the factory was already
// invoked (by TenantRegistry, keyed on the token's subject) before any tool
// argument existed.
function fakeFactory(_host: string, _port: number, user: string, _pass: string) {
  const mailbox = MAILBOXES[user];
  return {
    usable: false,
    connect: async function (this: any) {
      this.usable = true;
    },
    logout: async function (this: any) {
      this.usable = false;
    },
    list: async () => (mailbox?.folders ?? []).map((path) => ({ path })),
    getMailboxLock: async () => ({ release() {} }),
    search: async () => (mailbox?.messages ?? []).map((m) => m.uid),
    fetch: async function* (range: number[] | number, query: { envelope?: boolean; source?: boolean }) {
      const uids = Array.isArray(range) ? range : [range];
      for (const uid of uids) {
        const msg = mailbox?.messages.find((m) => m.uid === uid);
        if (!msg) continue;
        if (query.source) yield { uid, source: msg.source };
        else if (query.envelope) yield { uid, envelope: msg.envelope };
      }
    },
  } as any;
}

// Accepts exactly the fixed set of (mailbox, password) pairs declared above.
const verify = async (_h: string, _p: number, mailbox: string, pass: string) => pass === 'good-pw' && mailbox in MAILBOXES;

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ---------------------------------------------------------------------------
// Harness: build the real app exactly the way main.ts wires it (see that
// file's composition), and listen on an ephemeral loopback port.
// ---------------------------------------------------------------------------

let base: string;
let server: Server;

before(async () => {
  const db = openDb(':memory:');
  const clientsStore = new SqliteClientsStore(db);
  const credentials = new CredentialStore(db, randomBytes(32));
  const pending = new PendingStore(db);
  const tokens = new TokenStore(db);
  const provider = new MailcowOAuthProvider({
    clientsStore,
    codes: new CodeStore(db),
    tokens,
    ttls: { code: 60, access: 3600, refresh: 2592000 },
  });
  const registry = new TenantRegistry({ credentials, connector: fakeFactory });
  const issuerUrl = new URL('http://127.0.0.1');
  const consentDeps = { pending, credentials, provider, clientsStore, tokens, verify, imapHost: 'usagi', imapPort: 993 };
  provider.setOnAuthorize((client, params, res) =>
    res.redirect(
      beginConsent(consentDeps, res, {
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state,
        resource: params.resource?.href,
        scopes: params.scopes,
      }),
    ),
  );
  const app = buildApp({ provider, clientsStore, pending, credentials, tokens, registry, verify, issuerUrl, imapHost: 'usagi', imapPort: 993 });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function registerClient(
  overrides: { client_name?: string; redirect_uris?: string[] } = {},
): Promise<{ client_id: string }> {
  const res = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Test client',
      redirect_uris: ['https://claude/cb'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'none',
      ...overrides,
    }),
  });
  return (await res.json()) as { client_id: string };
}

type Enrolment = { access_token: string; refresh_token: string; client_id: string };

// The consent flow is bound to the browser that started it: /authorize sets
// an HttpOnly, path-scoped cookie and POST /consent requires it back. These
// helpers do what a browser does -- keep the Set-Cookie from /authorize and
// replay it -- so the enrolment path exercises the binding rather than
// bypassing it.
function cookieHeaderFrom(res: Response): string {
  const setCookie = res.headers.getSetCookie?.() ?? [];
  return setCookie.map((c) => c.split(';')[0]!).join('; ');
}

type Started = { handle: string; cookie: string; verifier: string; clientId: string };

async function startAuthorize(clientId: string, redirectUri = 'https://claude/cb'): Promise<Started> {
  const { verifier, challenge } = pkce();
  const authRes = await fetch(
    `${base}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=st`,
    { redirect: 'manual' },
  );
  assert.ok(authRes.headers.get('location'), 'authorize must redirect to the consent screen');
  const handle = new URL(authRes.headers.get('location')!, base).searchParams.get('handle')!;
  return { handle, cookie: cookieHeaderFrom(authRes), verifier, clientId };
}

function postConsent(handle: string, mailbox: string, cookie: string, password = 'good-pw'): Promise<Response> {
  return fetch(`${base}/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams({ handle, mailbox, app_password: password }),
  });
}

// Runs one full enrolment (DCR -> authorize -> consent -> token exchange)
// and returns the resulting token pair.
async function enrol(mailbox: string): Promise<Enrolment> {
  const reg = await registerClient();
  const { handle, cookie, verifier } = await startAuthorize(reg.client_id);

  const consentRes = await postConsent(handle, mailbox, cookie);
  assert.ok(consentRes.headers.get('location'), 'consent POST must redirect back to the client with a code');
  const cb = new URL(consentRes.headers.get('location')!);
  const code = cb.searchParams.get('code')!;
  assert.ok(code, 'callback redirect must carry an authorization code');

  const tokRes = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://claude/cb',
      client_id: reg.client_id,
      code_verifier: verifier,
    }),
  });
  assert.equal(tokRes.status, 200, 'token exchange with the matching verifier must succeed');
  const tok = (await tokRes.json()) as { access_token: string; refresh_token: string };
  return { access_token: tok.access_token, refresh_token: tok.refresh_token, client_id: reg.client_id };
}

// Both Accept types are required -- the SDK's streamable HTTP transport
// 406s a request that is missing either.
const MCP_ACCEPT = 'application/json, text/event-stream';

async function callTool(access: string, name: string, args: Record<string, unknown> = {}): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: MCP_ACCEPT, authorization: `Bearer ${access}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
  });
}

async function callToolText(access: string, name: string, args: Record<string, unknown> = {}): Promise<string> {
  const res = await callTool(access, name, args);
  return res.text();
}

async function refreshToken(refresh_token: string, client_id: string): Promise<Response> {
  return fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token, client_id }),
  });
}

// ---------------------------------------------------------------------------
// 1. Full OAuth 2.1 flow, end to end over real HTTP.
// ---------------------------------------------------------------------------

test('discovery documents are served', async () => {
  const as = await fetch(`${base}/.well-known/oauth-authorization-server`);
  assert.equal(as.status, 200);
  const meta = (await as.json()) as any;
  assert.ok(meta.token_endpoint && meta.authorization_endpoint && meta.registration_endpoint);
});

test('full enrolment yields working tokens, lists all six tools, and a tool call returns the enrolled mailbox data', async () => {
  const t = await enrol('harry@x');
  assert.ok(t.access_token && t.refresh_token);

  const listRes = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: MCP_ACCEPT, authorization: `Bearer ${t.access_token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  assert.equal(listRes.status, 200);
  const listText = await listRes.text();
  for (const name of ['current_mailbox', 'list_folders', 'list_recent', 'search_messages', 'get_message', 'list_attachments']) {
    assert.ok(listText.includes(name), `tools/list missing ${name}`);
  }

  const foldersText = await callToolText(t.access_token, 'list_folders');
  assert.ok(foldersText.includes('Harry-Sent'), 'list_folders must return the enrolled mailbox\'s own folders');
  assert.ok(foldersText.includes('INBOX'));
});

test('current_mailbox reflects the token subject', async () => {
  const t = await enrol('harry@x');
  const text = await callToolText(t.access_token, 'current_mailbox');
  assert.ok(text.includes('harry@x'));
});

// ---------------------------------------------------------------------------
// 2. Tenant isolation -- the most important property in the suite.
// ---------------------------------------------------------------------------

test('tenants are isolated across every mailbox-reading tool, sequentially', async () => {
  const h = await enrol('harry@x');
  const d = await enrol('dea@x');

  const hFolders = await callToolText(h.access_token, 'list_folders');
  const dFolders = await callToolText(d.access_token, 'list_folders');
  assert.ok(hFolders.includes('Harry-Sent') && !DEA_MARKERS.some((m) => hFolders.includes(m)));
  assert.ok(dFolders.includes('Dea-Archive') && !HARRY_MARKERS.some((m) => dFolders.includes(m)));

  const hRecent = await callToolText(h.access_token, 'list_recent');
  const dRecent = await callToolText(d.access_token, 'list_recent');
  assert.ok(hRecent.includes('Harry Secret Plan') && !DEA_MARKERS.some((m) => hRecent.includes(m)));
  assert.ok(dRecent.includes('Dea Confidential Memo') && !HARRY_MARKERS.some((m) => dRecent.includes(m)));

  const hSearch = await callToolText(h.access_token, 'search_messages');
  const dSearch = await callToolText(d.access_token, 'search_messages');
  assert.ok(hSearch.includes('Harry Secret Plan') && !DEA_MARKERS.some((m) => hSearch.includes(m)));
  assert.ok(dSearch.includes('Dea Confidential Memo') && !HARRY_MARKERS.some((m) => dSearch.includes(m)));

  const hMsg = await callToolText(h.access_token, 'get_message', { uid: 101 });
  const dMsg = await callToolText(d.access_token, 'get_message', { uid: 201 });
  assert.ok(hMsg.includes('ally@harry.example') && hMsg.includes('burrow') && !DEA_MARKERS.some((m) => hMsg.includes(m)));
  assert.ok(dMsg.includes('boss@dea.example') && dMsg.includes('Quarterly numbers') && !HARRY_MARKERS.some((m) => dMsg.includes(m)));

  const hAtt = await callToolText(h.access_token, 'list_attachments', { uid: 101 });
  const dAtt = await callToolText(d.access_token, 'list_attachments', { uid: 201 });
  assert.ok(hAtt.includes('harry-invoice.pdf') && !DEA_MARKERS.some((m) => hAtt.includes(m)));
  assert.ok(dAtt.includes('dea-invoice.pdf') && !HARRY_MARKERS.some((m) => dAtt.includes(m)));
});

test('tenant isolation holds under interleaved, concurrent requests (Promise.all, not sequential)', async () => {
  const h = await enrol('harry@x');
  const d = await enrol('dea@x');

  type Call = { who: 'harry' | 'dea'; tool: string; promise: Promise<string> };
  const calls: Call[] = [];
  // Fire several rounds of alternating, overlapping calls for both subjects
  // across multiple tools so requests are genuinely in flight at once, not
  // just issued back-to-back.
  for (let round = 0; round < 6; round++) {
    calls.push({ who: 'harry', tool: 'list_folders', promise: callToolText(h.access_token, 'list_folders') });
    calls.push({ who: 'dea', tool: 'list_folders', promise: callToolText(d.access_token, 'list_folders') });
    calls.push({ who: 'harry', tool: 'search_messages', promise: callToolText(h.access_token, 'search_messages') });
    calls.push({ who: 'dea', tool: 'search_messages', promise: callToolText(d.access_token, 'search_messages') });
    calls.push({ who: 'harry', tool: 'get_message', promise: callToolText(h.access_token, 'get_message', { uid: 101 }) });
    calls.push({ who: 'dea', tool: 'get_message', promise: callToolText(d.access_token, 'get_message', { uid: 201 }) });
  }

  const results = await Promise.all(calls.map(async (c) => ({ ...c, text: await c.promise })));

  let sawHarryMarker = false;
  let sawDeaMarker = false;
  for (const r of results) {
    const forbidden = r.who === 'harry' ? DEA_MARKERS : HARRY_MARKERS;
    const expected = r.who === 'harry' ? HARRY_MARKERS : DEA_MARKERS;
    assert.ok(!forbidden.some((m) => r.text.includes(m)), `${r.who}'s ${r.tool} leaked the other tenant's data under concurrency: ${r.text}`);
    if (expected.some((m) => r.text.includes(m))) {
      if (r.who === 'harry') sawHarryMarker = true;
      else sawDeaMarker = true;
    }
  }
  // Guards against a vacuously-passing test where every call errored out.
  assert.ok(sawHarryMarker, 'expected at least one concurrent harry call to actually return harry\'s own data');
  assert.ok(sawDeaMarker, 'expected at least one concurrent dea call to actually return dea\'s own data');
});

test('a hostile tool argument cannot steer search_messages to another subject\'s mailbox', async () => {
  const h = await enrol('harry@x');
  // Every argument that could plausibly name a mailbox is set to dea's
  // identity: `subject` is a real schema field (a text search filter);
  // `account`, `mailbox`, `user`, `tenant` are not part of the schema at
  // all, so they exercise whether unknown keys are honoured by mistake.
  const hostileText = await callToolText(h.access_token, 'search_messages', {
    folder: 'INBOX',
    subject: 'dea@x',
    from: 'dea@x',
    account: 'dea@x',
    mailbox: 'dea@x',
    user: 'dea@x',
    tenant: 'dea@x',
  });
  assert.ok(hostileText.includes('Harry Secret Plan'), 'harry\'s own mailbox must still be read despite the hostile arguments');
  assert.ok(!DEA_MARKERS.some((m) => hostileText.includes(m)), `hostile arguments steered the read into dea's mailbox: ${hostileText}`);
});

// ---------------------------------------------------------------------------
// 3. PKCE enforcement.
// ---------------------------------------------------------------------------

test('token exchange with a wrong PKCE verifier is rejected', async () => {
  const reg = await registerClient();
  const { handle, cookie } = await startAuthorize(reg.client_id);
  const consentRes = await postConsent(handle, 'harry@x', cookie);
  const code = new URL(consentRes.headers.get('location')!).searchParams.get('code')!;

  const tok = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: 'https://claude/cb', client_id: reg.client_id, code_verifier: 'wrong-verifier' }),
  });
  assert.equal(tok.status, 400);
  const body = (await tok.json()) as any;
  assert.equal(body.error, 'invalid_grant');
});

// ---------------------------------------------------------------------------
// 4. Bearer auth enforcement.
// ---------------------------------------------------------------------------

test('/mcp without a bearer token returns 401 with a WWW-Authenticate header carrying resource_metadata', async () => {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: MCP_ACCEPT },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  assert.equal(res.status, 401);
  const wwwAuth = res.headers.get('www-authenticate');
  assert.ok(wwwAuth, 'expected a WWW-Authenticate header');
  assert.match(wwwAuth!, /resource_metadata/);
});

// ---------------------------------------------------------------------------
// 5. Refresh rotation and reuse detection, over real HTTP.
// ---------------------------------------------------------------------------

test('replaying a consumed refresh token kills the whole chain, including the token it had already rotated to', async () => {
  const t1 = await enrol('harry@x');

  // The original access token works.
  assert.equal((await callTool(t1.access_token, 'current_mailbox')).status, 200);

  // Refresh once: legitimate rotation.
  const refreshRes = await refreshToken(t1.refresh_token, t1.client_id);
  assert.equal(refreshRes.status, 200);
  const t2 = (await refreshRes.json()) as { access_token: string; refresh_token: string };
  assert.notEqual(t2.access_token, t1.access_token);
  assert.notEqual(t2.refresh_token, t1.refresh_token);

  // The newly-rotated access token works.
  assert.equal((await callTool(t2.access_token, 'current_mailbox')).status, 200);

  // Replay the now-consumed original refresh token: rejected, and this is
  // the anti-theft trigger -- it must revoke the entire chain, not just
  // fail this one request.
  const replay = await refreshToken(t1.refresh_token, t1.client_id);
  assert.equal(replay.status, 400);

  // The chain is dead: the access token minted by the LEGITIMATE refresh
  // (never itself replayed) must now be unusable too.
  const afterReplay = await callTool(t2.access_token, 'current_mailbox');
  assert.equal(afterReplay.status, 401);

  // ...and so must the refresh token from that same rotation.
  const secondRefresh = await refreshToken(t2.refresh_token, t1.client_id);
  assert.equal(secondRefresh.status, 400);
});


// ---------------------------------------------------------------------------
// 6. The rogue-client phish, end to end over real HTTP.
//
// Dynamic client registration is open by specification: anyone can register
// a client with any client_name and any redirect_uri. The consent screen is
// therefore the only thing between that and a stranger's mailbox. This
// reproduces the exact sequence a reviewer ran successfully against the
// running app -- register with redirect_uri=https://evil.example/cb, drive
// /authorize, hand the victim the consent link -- and asserts each of the
// three properties that now stop it.
// ---------------------------------------------------------------------------

test('the consent page identifies the actual requesting client and its redirect origin, and claims no vendor', async () => {
  const rogue = await registerClient({ client_name: 'Mailbox Assistant', redirect_uris: ['https://evil.example/cb'] });
  const { handle } = await startAuthorize(rogue.client_id, 'https://evil.example/cb');

  const page = await fetch(`${base}/consent?handle=${encodeURIComponent(handle)}`);
  assert.equal(page.status, 200);
  const html = await page.text();

  assert.ok(html.includes('Mailbox Assistant'), 'the page must name the client that actually asked');
  assert.ok(html.includes('https://evil.example'), 'the page must show where the browser will be sent');
  assert.ok(!html.includes('Claude'), 'the page must not assert a vendor the request never mentioned');
});

test('an attacker cannot complete their own /authorize in a victim\'s browser', async () => {
  const rogue = await registerClient({ client_name: 'Mailbox Assistant', redirect_uris: ['https://evil.example/cb'] });
  // The attacker runs /authorize; the cookie lands in THEIR browser and is
  // deliberately not forwarded to the victim.
  const { handle } = await startAuthorize(rogue.client_id, 'https://evil.example/cb');

  const victimSubmit = await postConsent(handle, 'harry@x', '');

  assert.equal(victimSubmit.status, 200, 'expected the form back, not a 302 to the attacker');
  assert.equal(victimSubmit.headers.get('location'), null, 'no code may be issued to the attacker\'s redirect_uri');
  const body = await victimSubmit.text();
  assert.ok(/not started in this browser/i.test(body));
});

test('a fresh consent for a mailbox invalidates a token issued to a different client for that mailbox', async () => {
  // Stand in for the attacker's foothold: a real, working token bound to
  // harry@x, obtained through a complete legitimate flow of its own.
  const attacker = await enrol('harry@x');
  assert.equal((await callTool(attacker.access_token, 'current_mailbox')).status, 200);

  // Harry notices and re-adds the connector -- the recovery step a user can
  // actually perform without touching mailcow.
  const recovered = await enrol('harry@x');

  assert.equal((await callTool(attacker.access_token, 'current_mailbox')).status, 401, "the attacker's access token must be dead");
  assert.equal((await refreshToken(attacker.refresh_token, attacker.client_id)).status, 400, '...and it must not be able to rotate itself back');
  assert.equal((await callTool(recovered.access_token, 'current_mailbox')).status, 200, "harry's new token must work");
});

test('the consent GET and the 302 carrying the authorization code are both no-store', async () => {
  const reg = await registerClient();
  const { handle, cookie } = await startAuthorize(reg.client_id);

  const page = await fetch(`${base}/consent?handle=${encodeURIComponent(handle)}`);
  assert.match(page.headers.get('cache-control') ?? '', /no-store/);

  const done = await postConsent(handle, 'harry@x', cookie);
  assert.ok(done.headers.get('location')?.includes('code='));
  assert.match(done.headers.get('cache-control') ?? '', /no-store/, 'a 302 carrying a live code must not be cacheable');
});
