#!/bin/sh
# mailcp nginx guard — verify, and repair only when something is actually broken.
#
# WHY THIS EXISTS
# aaPanel regenerates a site vhost AND deletes
# /www/server/panel/vhost/nginx/extension/<site>/ every time that site is
# edited in its UI (Docker proxy setup, SSL renewal, rewrite rules). That
# removes the config this connector needs and reverts the TLS hardening.
# Symptom: OAuth discovery 404s from the document root, and Claude loops
# forever on the consent screen while the consent POST itself succeeds.
#
# Editing the site in aaPanel is a perfectly normal thing to do. This script
# makes that safe instead of forbidden.
#
# USAGE
#   reinstall-nginx.sh check    verify only, change nothing (exit 1 if broken)
#   reinstall-nginx.sh repair   repair if broken, else do nothing  [cron uses this]
#   reinstall-nginx.sh          same as repair, with verbose output
#
# A repair reloads nginx, which is shared with ~40 other sites, so it happens
# only when a check has actually failed, and never on a schedule.
set -eu

SITE=mailcp.mizutech.id
SRC=/www/dk_project/dk_app/mailcp/deploy/nginx-mcp.conf
V=/www/server/panel/vhost/nginx/$SITE.conf
E=/www/server/panel/vhost/nginx/extension/$SITE/mcp.conf
MAIN=/www/server/nginx/conf/nginx.conf
LOG=/var/log/mailcp-nginx-guard.log
MODE=${1:-repair}

log() { echo "$(date -Is) $*" >> "$LOG"; }
say() { [ "$MODE" = "check" ] || [ -t 1 ] && echo "$*" || true; }

problems=""
[ -f "$E" ] || problems="$problems extension-missing"
[ -f "$E" ] && ! grep -q "oauth-authorization-server" "$E" && problems="$problems extension-incomplete"
grep -q "TLSv1.1" "$V" && problems="$problems tls-reverted"
grep -q "mcp_authorize" "$MAIN" || problems="$problems zones-missing"

if [ "$MODE" = "check" ]; then
  if [ -n "$problems" ]; then echo "BROKEN:$problems"; exit 1; fi
  echo "healthy"; exit 0
fi

if [ -z "$problems" ]; then
  say "healthy - nothing to do"
  exit 0
fi

log "repairing:$problems"
say "repairing:$problems"

# zones belong in http{} - only the per-site part goes in the extension file
if ! grep -q "mcp_authorize" "$MAIN"; then
  sed -i "0,/^http\s*{/s//http {\n    limit_req_zone \$binary_remote_addr zone=mcp_authorize:10m rate=10r\/s;\n    limit_req_zone \$binary_remote_addr zone=mcp_token:10m     rate=20r\/s;\n    limit_req_zone \$binary_remote_addr zone=mcp_register:10m  rate=1r\/s;\n    limit_req_zone \$binary_remote_addr zone=mcp_consent:10m   rate=5r\/m;/" "$MAIN"
fi

mkdir -p "$(dirname "$E")"
sed -n "27,\$p" "$SRC" > "$E"
# aaPanel owns ssl_protocols/ssl_ciphers in the vhost; duplicating them is a hard nginx error
sed -i "/^ssl_protocols /d; /^ssl_ciphers /d" "$E"

sed -i "s|^\(\s*\)ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;|\1ssl_protocols TLSv1.2 TLSv1.3;|" "$V"
sed -i "s|^\(\s*\)ssl_ciphers EECDH+CHACHA20.*|\1ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;|" "$V"

if ! nginx -t 2>>"$LOG"; then
  log "ABORTED - nginx -t failed, no reload performed"
  say "ABORTED - nginx -t failed, see $LOG"
  exit 1
fi
nginx -s reload
log "repaired and reloaded"
say "repaired and reloaded"

for p in /.well-known/oauth-authorization-server /.well-known/oauth-protected-resource/mcp; do
  c=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: $SITE" "https://127.0.0.1$p" -k --max-time 8 || echo ERR)
  say "  $p -> $c"; log "  $p -> $c"
done
c=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H "Host: $SITE" https://127.0.0.1/mcp -k --max-time 8 || echo ERR)
say "  POST /mcp -> $c (expect 401)"; log "  POST /mcp -> $c"
