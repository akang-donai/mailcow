# mailcp.mizutech.id — read this before editing the site in aaPanel

Deployed copy of this file lives at
`/www/wwwroot/mailcp.mizutech.id/README-BEFORE-EDITING.md`, in the site's
document root, so it is found by anyone poking at the site in aaPanel's file
manager. It is not reachable over the web — the proxy catches every path.

This document root is intentionally empty. Nothing is served from it.

The site is a reverse proxy to a Docker container. The application lives at
`/www/dk_project/dk_app/mailcp` and listens on `127.0.0.1:8787`. It is an
OAuth 2.1 server that lets mizutech.id staff read their own mailbox through
Claude, so it is internet-facing and it stores encrypted mailbox credentials.

## The thing that will bite you

aaPanel regenerates this site's vhost and **deletes**
`/www/server/panel/vhost/nginx/extension/mailcp.mizutech.id/` every time the
site is edited in the panel — SSL renewal, proxy settings, rewrite rules,
anything at all. That directory holds config this connector cannot work
without.

The failure is not obvious, which is the dangerous part. The consent screen
still loads and still accepts a password. What breaks is OAuth discovery:
`/.well-known/oauth-*` starts being served from this empty document root and
returns 404, so Claude can never find the token endpoint and bounces back to
the consent screen. It looks like a stuck page, not a config problem.

## After any edit to this site, run

    /www/dk_project/dk_app/mailcp/deploy/reinstall-nginx.sh

Expected output ends with `200`, `200`, `401`.

A cron job runs `reinstall-nginx.sh repair` every 15 minutes, so an edit
self-corrects and running it by hand only skips the wait. It repairs only
when something is actually broken — it does not reload nginx on a schedule,
because nginx is shared with about forty other sites. What it did, and when,
is recorded in `/var/log/mailcp-nginx-guard.log`.

To see whether the config is currently intact without changing anything:

    /www/dk_project/dk_app/mailcp/deploy/reinstall-nginx.sh check

## The three pieces of custom config

1. `/www/server/panel/vhost/nginx/extension/mailcp.mizutech.id/mcp.conf`
   - `^~ /.well-known/oauth-*` — a longer prefix than aaPanel's generated
     `location /.well-known{ root ...; }`, so OAuth discovery reaches the
     application instead of this empty directory. This is the piece whose
     absence causes the loop described above.
   - `^~ /mcp` with `proxy_buffering off` — the MCP transport streams;
     aaPanel's own proxy block buffers.
   - `limit_req` on `/authorize`, `/token`, `/register` and `/consent`.
2. Four `limit_req_zone` lines in `http{}` in
   `/www/server/nginx/conf/nginx.conf`. Zones must be declared in `http{}`;
   the `limit_req` directives that reference them live in the file above.
3. `ssl_protocols` and `ssl_ciphers` in the **vhost itself**, pinned to
   TLS 1.2+. aaPanel defaults this site to TLS 1.1 with 3DES. These cannot
   live in the extension file: aaPanel emits its own copies afterwards, and a
   duplicate `ssl_ciphers` is a hard nginx error that fails `nginx -t`.

Source of truth for all of it is `deploy/nginx-mcp.conf` in the repository,
checked out at `/www/dk_project/dk_app/mailcp`.

## Do not

- Put application code in this document root. PHP is wired into this site; if
  a proxy rule ever went missing, source here would be served rather than
  404ing. An empty root fails safe.
- Add `ssl_protocols` or `ssl_ciphers` to the extension file. See point 3.
- Delete `/www/dk_project/dk_app/mailcp/deploy/secrets/key`. Every stored
  mailbox credential is encrypted with it and is cryptographically
  unrecoverable without it — every enrolled user would have to create a new
  mailcow app password and enrol again.
