import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ImapFlow } from 'imapflow';

import { loadAccounts, type Account } from './config.ts';
import { ConnectionRegistry } from './connections.ts';
import { registerLocalTools } from './local-tools.ts';

const accounts = loadAccounts(process.env);

const registry = new ConnectionRegistry(accounts, (account: Account) =>
  new ImapFlow({
    host: account.host,
    port: account.port,
    secure: true,
    auth: { user: account.user, pass: account.password },
    logger: false,
  }),
);

const server = new McpServer({ name: 'mailcow-imap', version: '0.2.0' });

registerLocalTools(server, {
  registry,
  accountLines: accounts.map((a) => `${a.name}  ${a.user}  ${a.host}:${a.port}`),
});

await server.connect(new StdioServerTransport());

const shutdown = async () => {
  await registry.closeAll();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
