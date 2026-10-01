#!/bin/sh
# Register the disposable Hydra client and start the headless consent app.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CA="$ROOT/build/test-pki/ca.pem"
curl -s --cacert "$CA" -X DELETE https://localhost:14445/admin/clients/warden-rp >/dev/null || true
curl -sf --cacert "$CA" -X POST https://localhost:14445/admin/clients -H 'content-type: application/json' -d '{
  "client_id": "warden-rp",
  "client_secret": "warden-hydra-disposable-secret-0123456789",
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "scope": "openid offline_access email profile",
  "redirect_uris": ["https://localhost:1/callback"],
  "post_logout_redirect_uris": ["https://localhost:1/logged-out"],
  "token_endpoint_auth_method": "client_secret_basic"
}' >/dev/null
PIDFILE="$ROOT/build/hydra-consent.pid"
[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
lsof -ti tcp:14446 -sTCP:LISTEN | xargs kill 2>/dev/null || true
NODE_EXTRA_CA_CERTS="$CA" nohup node "$ROOT/test/providers/interop/hydra-consent.mjs" </dev/null >"$ROOT/build/hydra-consent.log" 2>&1 &
echo $! >"$PIDFILE"
sleep 1
