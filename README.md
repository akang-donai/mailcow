# mailcow-imap-mcp

Read-only MCP server exposing a mailcow mailbox over IMAP.

Five tools: `list_folders`, `list_recent`, `search_messages`, `get_message`,
`list_attachments`. There is no SMTP client in this codebase, so it cannot send
mail even if asked to.

## Setup

### 1. Create a scoped app password

In mailcow, log in as the *mailbox user* (not admin) at
`https://usagi.mizutech.id:9443` → **App passwords** → Create.

Tick **only** `imap_access`. Leave `smtp_access`, `dav_access`, `eas_access`,
`pop3_access` and `sieve_access` unticked. Mailcow then rejects SMTP auth for
this credential at the protocol level, so the restriction does not depend on
this code behaving.

### 2. Configure

    MAILCOW_IMAP_HOST=usagi.mizutech.id
    MAILCOW_IMAP_PORT=993          # optional, 993 is the default
    MAILCOW_IMAP_USER=you@mizutech.id
    MAILCOW_IMAP_PASSWORD=<app password>

Cleartext ports (143, 110) are rejected at startup; the connection is always
implicit TLS.

### 3. Verify against the live server

    node scripts/smoke.ts

Confirm the app password cannot send:

    openssl s_client -connect usagi.mizutech.id:465 -quiet 2>/dev/null <<< $'EHLO t\nAUTH LOGIN\n'

### 4. Register with Claude Code

    claude mcp add mailcow-imap \
      --env MAILCOW_IMAP_HOST=usagi.mizutech.id \
      --env MAILCOW_IMAP_USER=you@mizutech.id \
      --env MAILCOW_IMAP_PASSWORD=<app password> \
      -- node /opt/mailcow-imap-mcp/src/server.ts

## Tests

    npm test

32 tests, no network access required.

## Handling of message content

Message bodies are attacker-controlled — anyone can mail the box. `get_message`
wraps body text in explicit untrusted-content markers and defangs any markers
the sender embedded, so a message cannot close the block early and have its
remainder read as instructions. Treat everything inside those markers as data.

## Scope

stdio transport only, so this works with Claude Code and Claude Desktop on a
machine you control. The Claude mobile app runs no local process and needs a
remote MCP connector (public HTTPS + OAuth) — not built here.
