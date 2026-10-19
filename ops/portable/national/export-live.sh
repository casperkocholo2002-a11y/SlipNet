#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-/root/slipnet-national-portable-$(date -u +%Y%m%dT%H%M%SZ).tgz}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
P="$TMP/slipnet-national-portable"
mkdir -p "$P/payload/tls" "$P/payload/guard"

XRAY=/opt/slipnet-a1-cdn-gateway/bin/xray
GW=/etc/slipnet-a1-cdn-gateway/server.json
PC=/etc/slipnet-a1-xhttp-prod/client-edge234.json
CERT=/etc/slipnet-a1-cdn-gateway/tls/fullchain.pem
KEY=/etc/slipnet-a1-cdn-gateway/tls/privkey.pem
UPD=/usr/local/sbin/slipnet-arvan-allowlist-update
RST=/usr/local/sbin/slipnet-arvan-allowlist-restore
CACHE=/var/lib/slipnet-arvan-guard

for f in "$XRAY" "$GW" "$PC" "$CERT" "$KEY" "$UPD" "$RST" "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/validate.sh"; do
  [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }
done

cp "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/validate.sh" "$P/"
cp "$XRAY" "$P/payload/xray"
cp "$GW" "$P/payload/gateway.json"
cp "$PC" "$P/payload/product-client.json"
cp "$CERT" "$P/payload/tls/fullchain.pem"
cp "$KEY" "$P/payload/tls/privkey.pem"
cp "$UPD" "$P/payload/guard/update"
cp "$RST" "$P/payload/guard/restore"
[[ -s "$CACHE/rules.nft" ]] && cp "$CACHE/rules.nft" "$P/payload/guard/rules.nft"
[[ -s "$CACHE/ips.txt" ]] && cp "$CACHE/ips.txt" "$P/payload/guard/ips.txt"

GATE_HOST="$(openssl x509 -in "$CERT" -noout -subject | sed -n 's/.*CN *= *//p')"
[[ -n "$GATE_HOST" ]] || GATE_HOST=gate.wordpresscsp.ir

cat >"$P/payload/meta.env" <<META
GATE_HOST=$GATE_HOST
GATE_PORT=443
SOCKS_PORT=19085
ARVAN_ALLOWLIST_URL=https://www.arvancloud.ir/fa/ips.txt
META

chmod 600 "$P/payload/gateway.json" "$P/payload/product-client.json" "$P/payload/tls/privkey.pem" "$P/payload/meta.env"
chmod 644 "$P/payload/tls/fullchain.pem" "$P/payload/guard/"*
chmod 755 "$P/install.sh" "$P/validate.sh" "$P/payload/xray" "$P/payload/guard/update" "$P/payload/guard/restore"

(
  cd "$P"
  find payload -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

tar -C "$TMP" -czf "$OUT" slipnet-national-portable
chmod 600 "$OUT"
echo "NATIONAL_PRIVATE_BUNDLE=$OUT"
sha256sum "$OUT"
