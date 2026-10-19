#!/usr/bin/env bash
set -Eeuo pipefail
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="$BASE/payload"
STATE=/var/lib/slipnet-portable-foreign
source "$P/meta.env"

echo "=== PRODUCT ==="
systemctl is-active slipnet-a1-xhttp-prod.service
systemctl show -p NRestarts slipnet-a1-xhttp-prod.service
ss -lntp | grep "127.0.0.1:$PRODUCT_PORT"

echo "=== FRONT ==="
source "$STATE/front-state"
systemctl is-active "$unit"
systemctl show -p NRestarts "$unit"

echo "=== TLS ==="
echo | openssl s_client -connect 127.0.0.1:443 -servername "$PUBLIC_HOST" -alpn h2 2>/dev/null | grep -E 'Protocol|Cipher|ALPN protocol|Verify return code' | tail -10
openssl x509 -in /etc/slipnet-portable-foreign/tls/fullchain.pem -noout -subject -issuer -dates

TEST_CFG=/run/slipnet-portable-foreign-selftest.json
TEST_LOG=/run/slipnet-portable-foreign-selftest.log
TEST_PORT=19091
python3 - "$TEST_CFG" "$PUBLIC_HOST" "$PRODUCT_PORT" <<'PY'
import json,sys
out,host,_=sys.argv[1:4]
s=json.load(open("/etc/slipnet-a1-xhttp-prod/server.json"))
ib=s["inbounds"][0]
uid=ib["settings"]["clients"][0]["id"]
path=ib["streamSettings"]["xhttpSettings"]["path"]
c={
 "log":{"loglevel":"error"},
 "inbounds":[{"listen":"127.0.0.1","port":19091,"protocol":"socks","settings":{"udp":False}}],
 "outbounds":[{
   "protocol":"vless",
   "settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":uid,"encryption":"none"}]}]},
   "streamSettings":{
     "network":"xhttp","security":"tls",
     "tlsSettings":{"serverName":host,"allowInsecure":False,"alpn":["h2"]},
     "xhttpSettings":{"host":host,"path":path,"mode":"packet-up"}
   }
 }]
}
open(out,"w").write(json.dumps(c))
PY

/opt/slipnet-a1-xhttp-prod/bin/xray run -test -config "$TEST_CFG"
/opt/slipnet-a1-xhttp-prod/bin/xray run -config "$TEST_CFG" >"$TEST_LOG" 2>&1 &
PID=$!
cleanup() {
  kill "$PID" 2>/dev/null || true
  rm -f "$TEST_CFG" "$TEST_LOG"
}
trap cleanup EXIT
for _ in $(seq 1 30); do
  ss -lnt | grep -q ":$TEST_PORT " && break
  sleep .1
done
CODE="$(curl -sS --socks5-hostname 127.0.0.1:$TEST_PORT --connect-timeout 6 --max-time 20 -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 || true)"
echo "SELFTEST_HTTP=$CODE"
[[ "$CODE" == 204 ]]
echo "FOREIGN_PACK_VALID=YES"
