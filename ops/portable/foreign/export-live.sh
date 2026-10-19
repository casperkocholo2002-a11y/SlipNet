#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-/root/slipnet-foreign-portable-$(date -u +%Y%m%dT%H%M%SZ).tgz}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
P="$TMP/slipnet-foreign-portable"
mkdir -p "$P/payload/tls"

XRAY=/opt/slipnet-a1-xhttp-prod/bin/xray
CFG=/etc/slipnet-a1-xhttp-prod/server.json
HOST="${SLIPNET_PUBLIC_HOST:-slipnet.wordpresscsp.ir}"

if [[ -x /usr/local/bin/caddy-naive ]]; then
  CADDY=/usr/local/bin/caddy-naive
elif [[ -x /opt/slipnet-portable-foreign/bin/caddy ]]; then
  CADDY=/opt/slipnet-portable-foreign/bin/caddy
elif [[ -x /usr/bin/caddy ]]; then
  CADDY=/usr/bin/caddy
else
  echo "no usable caddy binary found"
  exit 1
fi

for f in "$XRAY" "$CFG" "$CADDY" "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/validate.sh" "$SCRIPT_DIR/rollback.sh"; do
  [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }
done

PRODUCT_PATH="$(python3 - "$CFG" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o["inbounds"][0]["streamSettings"]["xhttpSettings"]["path"])
PY
)"

if [[ -s /etc/slipnet-portable-foreign/tls/fullchain.pem && -s /etc/slipnet-portable-foreign/tls/privkey.pem ]]; then
  CERT=/etc/slipnet-portable-foreign/tls/fullchain.pem
  KEY=/etc/slipnet-portable-foreign/tls/privkey.pem
else
  CERT_ROOT=/var/lib/caddy/.local/share/caddy/certificates
  CERT="$(find "$CERT_ROOT" -type f -path "*/$HOST/$HOST.crt" 2>/dev/null | head -1)"
  KEY="$(find "$CERT_ROOT" -type f -path "*/$HOST/$HOST.key" 2>/dev/null | head -1)"
fi
[[ -s "$CERT" && -s "$KEY" ]] || { echo "TLS certificate not found for $HOST"; exit 1; }

cp "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/validate.sh" "$SCRIPT_DIR/rollback.sh" "$P/"
cp "$XRAY" "$P/payload/xray"
cp "$CADDY" "$P/payload/caddy"
cp "$CFG" "$P/payload/server.json"
cp "$CERT" "$P/payload/tls/fullchain.pem"
cp "$KEY" "$P/payload/tls/privkey.pem"

cat >"$P/payload/meta.env" <<META
PUBLIC_HOST=$HOST
PRODUCT_PATH=$PRODUCT_PATH
PRODUCT_PORT=18922
META

chmod 600 "$P/payload/server.json" "$P/payload/tls/privkey.pem" "$P/payload/meta.env"
chmod 644 "$P/payload/tls/fullchain.pem"
chmod 755 "$P/install.sh" "$P/validate.sh" "$P/rollback.sh" "$P/payload/xray" "$P/payload/caddy"

(
  cd "$P"
  find payload -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

tar -C "$TMP" -czf "$OUT" slipnet-foreign-portable
chmod 600 "$OUT"
echo "FOREIGN_PRIVATE_BUNDLE=$OUT"
sha256sum "$OUT"
