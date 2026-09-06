# mailcow-imap-mcp

Read-only MCP server exposing one or more mailcow mailboxes over IMAP.

Six tools: `list_accounts`, `list_folders`, `list_recent`, `search_messages`,
`get_message`, `list_attachments`. There is no SMTP client in this codebase, so
it cannot send mail even if asked to.

Every tool requires an explicit `account`, and every line of output names the
account it came from — with several mailboxes configured, that is the only
thing distinguishing otherwise identical results.

## Setup

### 1. Create a scoped app password per mailbox

In mailcow, log in as the *mailbox user* (not admin) at
`https://usagi.mizutech.id:9443` → **App passwords** → Create.

Tick **only** `imap_access`. Leave `smtp_access`, `dav_access`, `eas_access`,
`pop3_access` and `sieve_access` unticked. `apppass_login()` in mailcow then
skips this credential for any service whose `<service>_access` column is not
`1`.

Two caveats worth knowing:

- The scoping applies to the **app password only**. `mailcowauth.php` falls
  through to `user_login()` when no app password matches, and that path checks
  the *mailbox's* attributes. Restricting an app password does not restrict the
  mailbox's own login password — which will still send mail.
- Verify the scoping rather than assuming it (step 3). A mistyped password is
  refused by SMTP too, which looks identical to a correctly scoped one.

### 2. Write the accounts file

Copy `accounts.example.json`, fill in the app passwords, and lock it down:

    cp accounts.example.json ~/.config/mailcow-mcp/accounts.json
    chmod 600 ~/.config/mailcow-mcp/accounts.json

```json
{
  "accounts": {
    "harry": { "host": "usagi.mizutech.id", "user": "harry@mizutech.id", "password": "..." },
    "admin": { "host": "usagi.mizutech.id", "user": "admin@mizutech.id", "password": "..." }
  }
}
```

The object key is the account name the tools take. `port` is optional and
defaults to 993; cleartext ports (143, 110) are rejected at startup, and so is
a file any user other than its owner can read.

One env var points at it:

    MAILCOW_ACCOUNTS_FILE=/home/you/.config/mailcow-mcp/accounts.json

Keeping the passwords in this file rather than in the MCP registration means
they never land in `~/.claude.json`, which is stored in cleartext.

### 3. Verify against the live server

    MAILCOW_ACCOUNTS_FILE=... node scripts/smoke.ts
    MAILCOW_ACCOUNTS_FILE=... node scripts/check-no-smtp.ts

Both take an optional account name to check just one. `check-no-smtp.ts`
exits non-zero unless *every* account passes, and a `PASS` requires both legs:
IMAP must accept the credential and SMTP must refuse that same credential.

| verdict | meaning |
|---|---|
| `scoped` | reads mail, cannot send |
| `can-send` | `smtp_access` is still enabled for this credential |
| `bad-credential` | IMAP refused it, so the SMTP result proves nothing |
| `inconclusive` | the SMTP reply could not be classified |

### 4. Register with Claude Code

    claude mcp add mailcow-imap \
      --env MAILCOW_ACCOUNTS_FILE=/home/you/.config/mailcow-mcp/accounts.json \
      -- node /opt/mailcow-imap-mcp/src/server.ts

## Tests

    npm test

61 tests, no network access required.

## Connections

Connections open on first use, not at startup, so one unreachable mailbox does
not stop the others from working. ImapFlow does not reconnect on its own and
Dovecot drops idle sessions, so the registry re-checks each connection before
handing it out and redials when needed. Concurrent callers share one dial
rather than racing.

## Handling of message content

Message bodies are attacker-controlled — anyone can mail these boxes.
`get_message` wraps body text in explicit untrusted-content markers and defangs
any markers the sender embedded, so a message cannot close the block early and
have its remainder read as instructions. Treat everything inside those markers
as data.

## Scope

stdio transport only, so this works with Claude Code and Claude Desktop on a
machine you control. The Claude mobile app runs no local process and needs a
remote MCP connector (public HTTPS + OAuth) — not built here.
