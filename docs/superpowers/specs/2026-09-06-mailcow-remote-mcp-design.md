# Remote MCP connector for mailcow (Step B)

Date: 2026-09-06
Status: approved design, not yet implemented

## Goal

Let any `mizutech.id` mailbox user read their own mail through Claude from a
phone, tablet or any browser, without installing anything locally.

Step A delivered a stdio MCP server that reads mailboxes over IMAP from a
machine the user controls. It cannot serve mobile: the Claude mobile app runs
no local process. This document designs the remote counterpart.

## Constraints established before designing

**Claude reaches the server from Anthropic's cloud, not from the user's
device.** The endpoint must therefore be publicly reachable. A VPN or overlay
network on the phone does not help.

**OAuth 2.1 is mandatory.** Claude's custom-connector flow performs discovery
and dynamic client registration against the server's origin and offers no
unauthenticated option.

**Mailcow's built-in OAuth2 cannot be reused.** It exists at
`data/web/oauth/{authorize,token,profile}.php` on bshaffer `^1.11`, but has no
PKCE (no `code_challenge` anywhere in the bundled library), no dynamic client
registration, no discovery documents, and a hardcoded `profile`-only scope.

**Verified reachability.** From Anthropic's network, `usagi.mizutech.id:9443`
answers 200 and `mailcp.mizutech.id:443` answers 403 from an empty document
root. Both confirm the edge forwards to the right hosts. An earlier probe
returned `ECONNREFUSED` for 443; the path was opened during design.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Who may enrol | any `mizutech.id` mailbox user, self-service | user's requirement |
| Credential source | user supplies their own `imap_access` app password | keeps every mailcow admin credential off the public host |
| Hosting | `mailcp.mizutech.id` on merbabu, in Docker | user's infrastructure |
| Authorization server | in-process, built on the MCP SDK's auth router | SDK supplies the protocol mechanics; identity here is only "proves control of a mailbox" |

### Rejected alternatives

**Service provisions app passwords via the mailcow admin API.** Smoother
signup, but requires a read-write admin key resident on an internet-facing
host. That key can delete mailboxes and domains, so one service compromise
becomes full mail-infrastructure compromise.

**Store users' mailbox passwords.** Simplest, and the worst outcome under
breach: those credentials authenticate to SMTP on this deployment, as measured
during Step A. An attacker would be able to send as every enrolled user.

**Self-hosted or hosted IdP (Keycloak, Zitadel, Auth0, WorkOS) behind the
SDK's `ProxyOAuthServerProvider`.** Mature OAuth someone else maintains, but
the app-password step still needs its own screen, so users authenticate twice.
An IdP mostly supplies a user database and login UI, neither of which this
system needs.

## Architecture

```
Claude cloud  (mobile / web / desktop)
      | HTTPS + OAuth 2.1 bearer
      v
143.20.10.19:443  ->  merbabu nginx (mailcp.mizutech.id)
      | proxy_pass 127.0.0.1:8787
      v
connector container  (node:24-alpine, non-root, read-only rootfs)
   |-- mcpAuthRouter (SDK)  /.well-known/*, /register, /authorize, /token, /revoke
   |-- consent page (ours)  mailbox + imap_access app password
   |-- /mcp                 StreamableHTTPServerTransport + bearerAuth
   \-- SQLite               clients, codes, tokens, encrypted credentials
      | IMAP 993 TLS
      v
usagi.mizutech.id  Dovecot
```

### Enrolment

1. User creates an `imap_access`-only app password in mailcow.
2. User adds a custom connector in Claude pointing at `https://mailcp.mizutech.id/mcp`.
3. Claude receives `401` with `WWW-Authenticate`, reads both discovery
   documents, registers via DCR, and opens `/authorize` with a PKCE challenge.
4. The consent page collects the user's address and app password.
5. The server opens a real IMAP connection to usagi to verify them. An invalid
   credential never becomes a token.
6. The app password is encrypted and stored, keyed by mailbox address. An
   authorization code is issued, bound to the PKCE challenge and that address.
7. Claude exchanges code and verifier for access and refresh tokens, both bound
   to the same address.

## Data model

SQLite (`node:sqlite`, built into Node 24), file mode 0600, stored outside any
document root.

```sql
oauth_clients        client_id PK, client_name, redirect_uris JSON,
                     grant_types, scope, created_at, last_used_at

authorization_codes  code_hash PK, client_id, subject, code_challenge,
                     redirect_uri, resource, expires_at, consumed_at

tokens               token_hash PK, kind('access'|'refresh'), client_id,
                     subject, scope, expires_at, revoked_at, rotated_from

credentials          subject PK, host, port, ciphertext, nonce,
                     verified_at, last_used_at, invalid_since
```

### Encryption of stored app passwords

AES-256-GCM via `node:crypto`. The key lives at `/etc/mailcp/key` mode 0400,
owned by the service user, bind-mounted read-only into the container. It is
never in the database, the image, a build layer, or an environment variable.

Each record carries a fresh 96-bit nonce. **The AAD is the subject**, so a
ciphertext copied from one row into another fails to decrypt rather than
returning another user's password.

### Tokens

Opaque, 256 bits from `randomBytes`, stored as SHA-256 and compared in constant
time. Opaque rather than JWT so revocation is immediate; a JWT stays valid
until expiry regardless of database state, which is the wrong property for
something that reads mail.

Plain SHA-256 is correct for these specifically because they are high-entropy
random values rather than user-chosen secrets. bcrypt or argon2 would defend
against guessing, which is not a threat to a 256-bit random string, and would
add latency to every request.

| Artefact | Lifetime | Notes |
|---|---|---|
| authorization code | 60 s | single use, `consumed_at` on exchange |
| access token | 1 h | opaque, checked against the database per request |
| refresh token | 30 d | rotated on every use |
| stored credential | until revoked | outlives tokens so users do not re-enrol monthly |

**Refresh rotation with reuse detection.** OAuth 2.1 requires rotation for
public clients, and Claude registers as one. Each refresh issues a new pair and
consumes the old. Presenting an already-consumed refresh token means two
parties hold it, so the whole token chain for that subject and client is
revoked and the user must re-authorise. Silent theft becomes a visible
re-login.

### Abuse controls

`/register` is open by specification. Rate limit per IP at nginx, cap total
clients, and prune registrations with no successful authorisation after seven
days. The consent screen remains the real gate: a registered client without a
valid mailbox app password obtains nothing.

Redirect URIs are matched exactly. No wildcards, no prefix matching.

## Tool surface

```
current_mailbox                                  address this token is bound to
list_folders
list_recent        (folder, limit)
search_messages    (folder, from, subject, since, unseen, limit)
get_message        (folder, uid, max_chars)
list_attachments   (folder, uid)
```

Step A's `account` parameter is **absent by design**. The mailbox is derived
from the token, never from a tool argument, or any enrolled user could name a
colleague's mailbox. Step A's `list_accounts` is also absent: enumerating
mailboxes would disclose the domain's staff list.

### Isolation

Tool handlers read the subject from the per-call `extra.authInfo`, never from a
closure captured at registration. Capturing it once at startup would serve
every user whichever mailbox enrolled first. This is the highest-severity
defect the design admits and is covered by dedicated tests.

The transport runs **stateless**: `sessionIdGenerator: undefined`, with a fresh
transport and `McpServer` per HTTP request, torn down afterwards. There is then
no shared mutable state between users for a session-confusion bug to inhabit.
For a read-only tool server with no server-initiated notifications, nothing is
given up.

Errors disclose nothing about other tenants. A failed lookup reports no message
with that UID in that folder for the caller's mailbox, never that it exists
elsewhere.

### Connections

The Step A registry keyed connections by a name from a static file. This one
keys by subject, never by anything client-supplied, and:

- decrypts the credential at dial time and does not cache it, so plaintext
  exists only for the duration of a connect
- evicts idle connections after 10 minutes rather than holding one open per
  enrolled user indefinitely
- caps total connections with LRU eviction and rate limits per subject so one
  user cannot hammer Dovecot through the service
- retains Step A's lazy connect and reconnect-on-unusable behaviour

When a stored app password stops working, `invalid_since` is set and tools
return a re-authorisation message rather than retrying against Dovecot.

### Message content

`get_message` keeps Step A's untrusted-content markers and marker defanging.
Bodies are attacker-controlled — anyone can mail these boxes — and here they
are read by an agent with tools, on behalf of nine people rather than one.

## Deployment

**Project:** `/www/dk_project/dk_app/mailcp/`, image `node:24-alpine` pinned by
digest, which also fixes the experimental `node:sqlite` API to one runtime.

**Binding:** `127.0.0.1:8787:8787`. Never `0.0.0.0` — several containers on
this host publish on all interfaces, and doing so here would let anything on
`192.168.57.0/24` bypass nginx, and with it TLS, rate limits and security
headers.

**Container:** non-root user, `read_only: true`, `cap_drop: ALL`,
`no-new-privileges`, tmpfs `/tmp`, json-file log rotation.

**Volumes:** `./secrets/key -> /etc/mailcp/key` read-only 0400, and
`./data -> /var/lib/mailcp` 0700. Secrets never appear in `environment:`, which
is readable via `docker inspect` and in the panel UI.

**nginx.** The panel's Docker proxy generates the base configuration. Two
overrides go in
`/www/server/panel/vhost/nginx/extension/mailcp.mizutech.id/mcp.conf`, which
survives panel edits:

1. The vhost contains `location ~ \.well-known { allow all; }`. A regex
   location outranks a prefix location, so both OAuth discovery documents would
   be served from the empty document root and 404. Ours are declared `^~`,
   which beats regex.
2. `proxy_buffering off` and an extended read timeout for the streamed
   transport, `proxy_http_version 1.1`, TLS pinned to 1.2+ with 3DES dropped
   for this vhost only, and `X-Frame-Options: DENY` plus a restrictive CSP on
   the consent page, since a framable OAuth consent screen is a clickjacking
   target.

`limit_req` zones on `/register`, `/token` and `/authorize`.

Configuration is verified by fetching the metadata URL from outside the
network, the same probe that detected the missing 443 forward, rather than
assuming the configuration took effect.

## Testing

**Unit, no network.** Authorization code single use and replay rejection; PKCE
verifier mismatch and missing challenge; exact redirect-URI matching including
near-miss and prefix attacks; refresh rotation and chain revocation on reuse;
token hashing and constant-time comparison; AES-GCM round trip and decryption
failure when the AAD names a different subject.

**Isolation.** Two subjects driven through one running server, asserting
neither observes the other's folders, messages or UIDs, including under
interleaved requests.

**Integration.** The express application on an ephemeral port with a fake IMAP
verifier, driving discovery, registration, authorisation, code exchange, an
authenticated `/mcp` call, refresh and revocation.

**Live.** One real mailbox enrolled from Claude mobile, which is the only test
that exercises the whole path.

## Accepted risks

**Self-service for the whole domain.** A compromise of this service exposes the
mail of every enrolled user, not one inbox. Chosen deliberately over a fixed
user list.

**Shared host.** merbabu runs 38 nginx vhosts plus MySQL, PostgreSQL, PHP,
Tomcat and aaPanel, and sits on the same `/24` as the mail server. Docker
contains a compromise of this service away from the others; it does not protect
this service from them. A compromise of any other site lands on a host that can
read the bind-mounted key and database as root. A dedicated public host would
remove this, at the cost of new infrastructure.

**Experimental SQLite API.** Mitigated by pinning the image digest; a Node
upgrade requires re-testing.

## Out of scope

Sending mail. There is no SMTP client in the codebase and the credentials are
scoped to `imap_access`, verified by `scripts/check-no-smtp.ts`.
