# Deploying the mailcow IMAP MCP remote connector

Operator runbook for running this service on `merbabu` (Debian 12, Docker,
aaPanel) as `https://mailcp.mizutech.id`. No knowledge of the source is
assumed beyond what's in this file.

Project directory on the host: `/www/dk_project/dk_app/mailcp/`. Everything
below assumes commands are run from there (a copy or checkout of this repo,
with this `deploy/` directory present).

Application code deliberately does **not** live under
`/www/wwwroot/mailcp.mizutech.id` -- that document root exists but is empty
by design. It has `include enable-php-85.conf`, so if the nginx proxy rule
in step 3 were ever missing or misconfigured, a document root containing our
source would serve it directly instead of 404ing. An empty root fails safe.

## 1. Generate the encryption key

```bash
mkdir -p data secrets
chmod 700 data
head -c 32 /dev/urandom > secrets/key
chmod 400 secrets/key
```

This is the 256-bit AES-GCM key every stored mailbox app password is
encrypted with (`CredentialStore` in `src/remote/store.ts`).

**Back this file up somewhere outside this host.** If it's lost, every
credential in the database becomes permanently undecryptable -- not just
hard to recover, cryptographically gone. There is no recovery path except
wiping the credentials table and having every enrolled user redo the
consent flow (a new mailbox app password each). Treat `secrets/key` with
the same care as a disk-encryption key or a root CA private key: back it up
encrypted, offline, and know who is allowed to touch it.

## 2. Bring the stack up

**Pin the base image by digest before the first build.** Do this now, not
after — `deploy/Dockerfile` as checked in builds against the floating
`node:24-alpine` tag, and once the build command further down has built and
started the container against it, you've already taken on the exact risk
this pin exists to prevent.

```bash
docker pull node:24-alpine
docker inspect --format='{{index .RepoDigests 0}}' node:24-alpine
# node:24-alpine@sha256:<digest>
```

Put that `node:24-alpine@sha256:...` value in `deploy/Dockerfile`'s `FROM`
line. Two independent reasons this matters here, not just general hygiene:

- `node:sqlite` (used by `src/remote/db.ts`) is still an **experimental**
  Node API. Its on-disk format and behavior can shift between Node point
  releases. Pinning the image by digest pins the exact Node build this
  database was created and is read by, so a routine `docker compose
  up -d --build` months from now can't silently move the container onto a
  different `node:sqlite` implementation underneath an existing database.
- A floating `:alpine` tag can change under you on any rebuild (security
  patches, base image bumps). A digest is the only thing that guarantees
  "the image I tested is the image running in production."

Only once `deploy/Dockerfile` has been edited to reference the pinned
digest:

```bash
docker compose up -d --build
```

Check the container came up and is passing its healthcheck:

```bash
docker compose ps
docker compose logs -f mailcp
```

`docker compose ps` should show `healthy` after ~10-40 seconds
(`start_period` + first probe). The healthcheck hits
`/.well-known/oauth-authorization-server` on the container's own loopback
address using `wget` (bundled with Alpine via BusyBox; the image has no
`curl`). `restart: unless-stopped` only restarts a container that has
*exited* -- it does nothing for a process that's still running but wedged,
which is exactly the case this healthcheck exists to catch.

### Why `read_only: true` works with a SQLite database

The compose file sets `read_only: true` on the container's root filesystem.
The two things this process needs to write both land outside that root:
`/tmp` (a tmpfs mount) and `/var/lib/mailcp` (the `./data` bind mount).
`node:sqlite` opens the database in WAL mode
(`PRAGMA journal_mode=WAL` in `src/remote/db.ts`), which writes two
additional files alongside the main one -- `mailcp.sqlite-wal` and
`mailcp.sqlite-shm` -- on every write transaction. Because the *whole*
`/var/lib/mailcp` directory is bind-mounted (not just the `.sqlite` file
itself), those sibling files land in the same writable mount and nothing
about `read_only: true` interferes with them. If you ever change this to
mount only the database file itself, WAL writes will fail.

## 3. Install the nginx override

Read `deploy/nginx-mcp.conf` in full before installing it -- it has two
separate install points and getting them backwards breaks `nginx -t`:

1. The `limit_req_zone` lines at the top of that file are only valid in
   nginx's `http {}` context. Add them to the **main** nginx config's
   `http` block (aaPanel: Nginx plugin -> config editor for the global
   `nginx.conf`), not to the per-site file in step 2.
2. The rest of the file (the `location` blocks, the `limit_req` directives
   that reference those zones by name, and the TLS settings) installs to:

   ```
   /www/server/panel/vhost/nginx/extension/mailcp.mizutech.id/mcp.conf
   ```

   Use that exact path. aaPanel regenerates the main per-site vhost file
   whenever the site is edited through its UI (SSL renewal, rewrite rules,
   etc.), which would silently wipe out a hand-edited addition to that
   file. The `extension/` directory is included from the site's `server {}`
   block and survives those rewrites.

The existing vhost already contains `location ~ \.well-known { allow all; }`
as a **regex** location. Regex locations outrank prefix locations in nginx's
matching order, so without the `^~` modifier our two
`/.well-known/oauth-*` locations would lose to that rule and be served
(404) from the empty document root -- OAuth discovery would fail before a
client ever got as far as `/authorize`. `nginx-mcp.conf` declares them
`^~`, which beats a regex location.

Then:

```bash
nginx -t
nginx -s reload
```

`nginx -t` cannot fully validate this repo's copy of the file in isolation
(it references zones and sits inside a server block it doesn't itself
define) -- always run it on the host, against the real merged config, after
installing both parts above.

## 4. Verify from OUTSIDE the network

Do this from a machine that is **not** merbabu and not on its LAN -- a
laptop off-network, a phone on cellular data, a cloud shell, anything that
reaches `mailcp.mizutech.id` the same way Claude's servers will. A prior
check of this exact deployment found port 443 unreachable from the public
internet while every local check on the host looked completely fine (the
proxy in front of merbabu wasn't forwarding it). Curling from merbabu or
from its LAN cannot catch that class of failure.

```bash
curl -s https://mailcp.mizutech.id/.well-known/oauth-authorization-server
```

Expected: HTTP 200, JSON body containing `"registration_endpoint"`. If this
404s, the `^~` regex-precedence fix in step 3 didn't get installed or
`nginx -s reload` didn't pick it up.

```bash
curl -si -X POST https://mailcp.mizutech.id/mcp
```

Expected: HTTP 401, with a `WWW-Authenticate` header present. This is the
MCP SDK's bearer-auth challenge, and confirms the request actually reached
the container rather than nginx or something else answering on its behalf.

### Also verify the TLS pin actually took effect

`nginx-mcp.conf`'s `ssl_protocols`/`ssl_ciphers` lines are legal inside the
per-site `server {}` block, but nginx applies **last one wins** within a
context. If aaPanel's own vhost-managed SSL block emits its own
`ssl_protocols` *after* the point where it includes the `extension/`
directory, your pin is silently overridden — `nginx -t` has no way to warn
about this, because both directives are individually valid; only their
order matters.

On the host, check which value actually won:

```bash
nginx -T | grep -A1 ssl_protocols
```

Expected: `ssl_protocols TLSv1.2 TLSv1.3;` for the `mailcp.mizutech.id`
server block. If it instead shows the panel default (typically including
`TLSv1.1`), the extension include is being loaded too early relative to
the panel's own SSL block — the pin is not living, even though `nginx -t`
passed and the site is otherwise reachable.

Then, from the same outside-the-network machine as the checks above,
confirm the server itself refuses a TLS 1.1 handshake:

```bash
openssl s_client -connect mailcp.mizutech.id:443 -tls1_1
```

Expected (pin is working): the connection fails — something like
`ssl_choose_client_version:unsupported protocol` or
`tlsv1 alert protocol version`, with no certificate printed and no
`Cipher is` line showing a negotiated cipher. If instead you get a
successful handshake (a certificate chain, `SSL-Session:`, and
`Protocol  : TLSv1.1`), the pin did not take effect server-side — go back
to the `nginx -T` check above.

Note: some OpenSSL builds (notably recent Debian/Ubuntu defaults and
Homebrew's OpenSSL 3.x) disable TLS 1.1 entirely at compile time and will
refuse to even attempt the handshake, printing something like
`unsupported protocol` before a single packet leaves the machine. That is
a **client-side** refusal and proves nothing about the server. If you see
this, either run the command from a machine/container with an older
OpenSSL (e.g. `docker run --rm alpine/openssl s_client -connect
mailcp.mizutech.id:443 -tls1_1`, since many minimal images still ship
OpenSSL 1.1) or fall back to `nginx -T` alone as your evidence.

Only proceed to step 5 once all three checks — discovery document, `/mcp`
401, and the TLS pin — pass from outside the network.

## 5. Add the connector in Claude

Each user must first create a mailcow app password scoped to **IMAP access
only** (mailcow: user panel -> App Passwords -> new password, select only
`imap_access` -- not `smtp_access`, not full access). This connector only
ever needs to read mail; there is no reason to hand it a credential that
can also send.

Then, in Claude:

- Settings -> Connectors -> Add custom connector
- URL: `https://mailcp.mizutech.id/mcp`
- Complete the consent screen that appears with the mailbox address and the
  `imap_access`-only app password just created. The consent screen proves
  the password works (it does a live IMAP login) before storing anything or
  issuing a token.
- Ask Claude to list your folders as a smoke test.

Each mailcow user enrolls themselves this way; nobody needs a shared or
admin credential to use the connector.

## 6. Rollback

```bash
docker compose down
```

Remove the extension config so nginx stops proxying to a stopped container:

```bash
rm /www/server/panel/vhost/nginx/extension/mailcp.mizutech.id/mcp.conf
nginx -t && nginx -s reload
```

Also remove the `limit_req_zone` lines added to the main `nginx.conf` in
step 3 if nothing else on the host uses those zone names (they're harmless
to leave, but there's no reason to keep dead config). `data/` and
`secrets/key` are left untouched by this rollback -- delete them yourself
only if you intend this to be permanent and understand that doing so
destroys every stored credential (see step 1).

## What this deployment does NOT protect against

merbabu is a shared host: roughly 38 other nginx vhosts, MySQL, PostgreSQL,
PHP, and aaPanel itself run alongside this container, and the host sits on
the same `/24` as the mail server (`usagi.mizutech.id`). The container
hardening in `docker-compose.yml` (`read_only`, `cap_drop: ALL`,
non-root user, no published ports beyond loopback) contains a compromise
*of this service* so it can't easily be used as a stepping stone to
everything else on the box.

It does **not** work in the other direction. A compromise of any of those
other 38 sites, or of MySQL/PostgreSQL/PHP/aaPanel, lands on a host that
can read `secrets/key` and `data/mailcp.sqlite` directly off disk as root
(or as any user with access equivalent to root) -- Docker's isolation is
irrelevant at that point, because the attacker isn't going through the
container at all. If that isolation matters more than the convenience of
running this alongside everything else already on merbabu, the fix is a
dedicated host, not a stronger container.
