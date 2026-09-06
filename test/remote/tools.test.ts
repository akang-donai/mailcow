import { test } from 'node:test';
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { subjectFromExtra, registerRemoteTools } from '../../src/remote/tools.ts';
import { TenantRegistry } from '../../src/remote/tenant-connections.ts';

// ---------------------------------------------------------------------------
// subjectFromExtra: the isolation-critical helper. Every tool derives the
// mailbox to act on by calling this with the per-call `extra`, never from a
// tool argument and never from anything captured at server-construction time.
// ---------------------------------------------------------------------------

test('subjectFromExtra reads the subject from authInfo.extra', () => {
  assert.equal(subjectFromExtra({ authInfo: { extra: { subject: 'harry@x' } } } as any), 'harry@x');
});

test('subjectFromExtra throws when authInfo is missing', () => {
  assert.throws(() => subjectFromExtra({} as any), /unauthenticated/i);
});

test('subjectFromExtra throws when subject is missing', () => {
  assert.throws(() => subjectFromExtra({ authInfo: { extra: {} } } as any), /subject/i);
});

test('subjectFromExtra ignores any subject-like field outside authInfo', () => {
  // A tool argument named subject must never be honoured.
  assert.throws(() => subjectFromExtra({ subject: 'attacker@x', authInfo: { extra: {} } } as any), /subject/i);
});

// ---------------------------------------------------------------------------
// Test harness: a fake CredentialStore and a fake IMAP connector, wired
// through a real TenantRegistry and a real McpServer connected over the
// SDK's in-memory transport. authInfo is attached per-message via the
// transport's `send(message, { authInfo })`, exactly like a real bearer
// token verified per-request by the HTTP layer -- never captured once at
// startup.
// ---------------------------------------------------------------------------

function fakeCredentialStore() {
  const creds = new Map<string, { host: string; port: number; appPassword: string }>();
  const invalidated: string[] = [];
  return {
    put(subject: string, host: string, port: number, appPassword: string) {
      creds.set(subject, { host, port, appPassword });
    },
    get(subject: string) {
      return creds.get(subject) ?? null;
    },
    markInvalid(subject: string) {
      invalidated.push(subject);
    },
    touch() {},
    invalidated,
  };
}

type UserFixture = { folders?: string[]; connectError?: Error; listError?: Error };

function connectorFor(byUser: Record<string, UserFixture>) {
  return (_host: string, _port: number, user: string, _pass: string) => {
    const fixture = byUser[user] ?? {};
    const client: any = {
      usable: false,
      connect: async () => {
        if (fixture.connectError) throw fixture.connectError;
        client.usable = true;
      },
      logout: async () => {
        client.usable = false;
      },
      list: async () => {
        if (fixture.listError) throw fixture.listError;
        return (fixture.folders ?? []).map((path) => ({ path }));
      },
      getMailboxLock: async () => ({ release: () => {} }),
      search: async () => [],
      fetch: async function* () {},
    };
    return client;
  };
}

function authInfoFor(subject: string) {
  return { token: 'tok', clientId: 'client', scopes: [], extra: { subject } };
}

async function harness(byUser: Record<string, UserFixture>) {
  const credentials = fakeCredentialStore();
  for (const subject of Object.keys(byUser)) {
    credentials.put(subject, 'usagi', 993, `${subject}-pw`);
  }
  const registry = new TenantRegistry({ credentials: credentials as any, connector: connectorFor(byUser) });

  const server = new McpServer({ name: 'test', version: '0.0.0' });
  registerRemoteTools(server, { registry, credentials: credentials as any });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const pending = new Map<number, (msg: any) => void>();
  clientTransport.onmessage = (msg: any) => {
    const resolve = pending.get(msg.id);
    if (resolve) {
      pending.delete(msg.id);
      resolve(msg);
    }
  };
  await server.connect(serverTransport);
  await clientTransport.start();

  let nextId = 1;
  async function callTool(name: string, args: Record<string, unknown>, subject?: string) {
    const id = nextId++;
    const p = new Promise<any>((resolve) => pending.set(id, resolve));
    await clientTransport.send(
      { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } } as any,
      { authInfo: subject ? authInfoFor(subject) : undefined },
    );
    const msg = await p;
    return msg.result;
  }

  return { callTool, credentials };
}

function textOf(result: any): string {
  return result.content[0].text;
}

// ---------------------------------------------------------------------------
// Wiring proof: subject comes from the per-call authInfo, not from a
// startup-time closure. Register the tools exactly once, then drive two
// calls for two different subjects over the same connection.
// ---------------------------------------------------------------------------

test('list_folders resolves the mailbox from the per-call subject, not a captured one', async () => {
  const { callTool } = await harness({
    'harry@x': { folders: ['INBOX', 'Harry-Only'] },
    'dea@x': { folders: ['INBOX', 'Dea-Only'] },
  });

  const harryResult = await callTool('list_folders', {}, 'harry@x');
  const deaResult = await callTool('list_folders', {}, 'dea@x');

  assert.match(textOf(harryResult), /Harry-Only/);
  assert.doesNotMatch(textOf(harryResult), /Dea-Only/);

  assert.match(textOf(deaResult), /Dea-Only/);
  assert.doesNotMatch(textOf(deaResult), /Harry-Only/);
});

test('a tool call with no authenticated subject fails rather than falling back to any mailbox', async () => {
  const { callTool } = await harness({ 'harry@x': { folders: ['INBOX'] } });
  const result = await callTool('list_folders', {}, undefined);
  assert.equal(result.isError, true);
  assert.match(textOf(result), /unauthenticated/i);
});

// ---------------------------------------------------------------------------
// guard(): the three-way error split.
// ---------------------------------------------------------------------------

test('an IMAP authentication failure marks the credential invalid and asks the user to re-authorise', async () => {
  const authErr: any = new Error('AUTHENTICATIONFAILED');
  authErr.authenticationFailed = true;
  const { callTool, credentials } = await harness({
    'harry@x': { connectError: authErr },
  });

  const result = await callTool('list_folders', {}, 'harry@x');

  assert.deepEqual(credentials.invalidated, ['harry@x']);
  assert.match(textOf(result), /re-?authoris|re-?authoriz|remove.*re-?add/i);
});

test('a transient IMAP error does NOT mark the credential invalid, and reports a distinct temporary-failure message', async () => {
  const { callTool, credentials } = await harness({
    'harry@x': { listError: new Error('read ECONNRESET') },
  });

  const result = await callTool('list_folders', {}, 'harry@x');

  assert.deepEqual(credentials.invalidated, []);
  const message = textOf(result);
  assert.doesNotMatch(message, /re-?authoris|re-?authoriz/i);
  assert.match(message, /try again|temporary|moment/i);
});

test('CredentialUnavailableError does NOT mark the credential invalid', async () => {
  // No credential stored for this subject at all: TenantRegistry.get throws
  // CredentialUnavailableError. There is nothing to invalidate.
  const { callTool, credentials } = await harness({});

  const result = await callTool('list_folders', {}, 'stranger@x');

  assert.deepEqual(credentials.invalidated, []);
  assert.match(textOf(result), /re-?authoris|re-?authoriz|remove.*re-?add/i);
});

test('the transient-failure message and the re-authorisation message are distinct', async () => {
  const authErr: any = new Error('AUTHENTICATIONFAILED');
  authErr.authenticationFailed = true;
  const { callTool: callAuthFail } = await harness({ 'harry@x': { connectError: authErr } });
  const { callTool: callTransient } = await harness({ 'harry@x': { listError: new Error('boom') } });

  const reauthMessage = textOf(await callAuthFail('list_folders', {}, 'harry@x'));
  const transientMessage = textOf(await callTransient('list_folders', {}, 'harry@x'));

  assert.notEqual(reauthMessage, transientMessage);
});
