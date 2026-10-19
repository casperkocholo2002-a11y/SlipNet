#!/usr/bin/env bash
set -Eeuo pipefail
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BASE/payload/meta.env"

echo "=== CORE SERVICES ==="
for s in slipnet-a1-xhttp-prod-client.service slipnet-a1-cdn-gateway.service; do
  printf '%s=' "$s"
  systemctl is-active "$s"
done

echo "=== SUPPORT SERVICES ==="
for s in slipnet-arvan-allowlist-restore.service slipnet-arvan-allowlist-update.timer; do
  printf '%s=' "$s"
  systemctl is-active "$s"
done

echo "=== RESTARTS ==="
systemctl show -p NRestarts slipnet-a1-xhttp-prod-client.service slipnet-a1-cdn-gateway.service

echo "=== LISTEN ==="
ss -lntp | grep -E '127\.0\.0\.1:19085|:443 '

echo "=== RETURN ROUTE ==="
RULES="$(ip -4 rule show)"
if systemctl is-active --quiet slipnet-portable-return-route.service 2>/dev/null; then
  echo "RETURN_ROUTE_OWNER=portable"
elif grep -q 'sport 443 lookup main' <<<"$RULES"; then
  echo "RETURN_ROUTE_OWNER=existing-compatible"
else
  echo "required sport 443 -> main rule missing"
  exit 1
fi
grep 'sport 443 lookup main' <<<"$RULES"

echo "=== FIREWALL ==="
nft list chain inet slipnet_cdn_guard input

echo "=== LOCAL TLS ==="
echo | openssl s_client -connect 127.0.0.1:443 -servername "$GATE_HOST" -alpn h2 2>/dev/null | grep -aE 'Protocol|Cipher|ALPN protocol|Verify return code' | tail -10

echo "=== FOREIGN EGRESS ==="
code="$(curl -sS --socks5-hostname 127.0.0.1:19085 --connect-timeout 8 --max-time 20 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 || true)"
echo "HTTP=$code"
[[ "$code" == "204" ]] || { echo "foreign egress failed"; exit 1; }

echo "NATIONAL_PACK_VALID=YES"
