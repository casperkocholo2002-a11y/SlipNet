#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="$BASE/payload"
STATE=/var/lib/slipnet-portable-foreign
[[ -d "$P" ]] || { echo "payload missing"; exit 1; }

cd "$BASE"
sha256sum -c SHA256SUMS
source "$P/meta.env"

for x in systemctl python3 openssl ss curl; do
  command -v "$x" >/dev/null || { echo "missing dependency: $x"; exit 1; }
done

FRONT_MODE=
CADDY_BIN=
CADDY_CFG=
CADDY_UNIT=

if systemctl is-active --quiet slipnet-portable-foreign-caddy.service 2>/dev/null; then
  FRONT_MODE=standalone
elif ss -H -lnt "sport = :443" | grep -q .; then
  if systemctl is-active --quiet slipgate-mobile.service 2>/dev/null      && [[ -x /usr/local/bin/caddy-naive ]]      && [[ -f /etc/slipgate/tunnels/mobile/Caddyfile ]]; then
    FRONT_MODE=coexist
    CADDY_BIN=/usr/local/bin/caddy-naive
    CADDY_CFG=/etc/slipgate/tunnels/mobile/Caddyfile
    CADDY_UNIT=slipgate-mobile.service
  else
    echo "port 443 is occupied by an unknown front; aborting"
    ss -lntp "sport = :443" || true
    exit 1
  fi
else
  FRONT_MODE=standalone
fi

id -u slipnet-a1-xhttp-prod >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin slipnet-a1-xhttp-prod
id -u slipnet-foreign-caddy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin slipnet-foreign-caddy

install -d -m 0755 /opt/slipnet-a1-xhttp-prod/bin
install -d -m 0750 -o root -g slipnet-a1-xhttp-prod /etc/slipnet-a1-xhttp-prod
install -d -m 0750 -o root -g slipnet-foreign-caddy /etc/slipnet-portable-foreign/tls
install -d -m 0700 "$STATE"

install -m 0755 "$P/xray" /opt/slipnet-a1-xhttp-prod/bin/xray
install -m 0640 -o root -g slipnet-a1-xhttp-prod "$P/server.json" /etc/slipnet-a1-xhttp-prod/server.json
install -m 0644 -o root -g slipnet-foreign-caddy "$P/tls/fullchain.pem" /etc/slipnet-portable-foreign/tls/fullchain.pem
install -m 0640 -o root -g slipnet-foreign-caddy "$P/tls/privkey.pem" /etc/slipnet-portable-foreign/tls/privkey.pem

cat >/etc/systemd/system/slipnet-a1-xhttp-prod.service <<'UNIT'
[Unit]
Description=SlipNet A1 portable Foreign XHTTP product
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=slipnet-a1-xhttp-prod
Group=slipnet-a1-xhttp-prod
ExecStart=/opt/slipnet-a1-xhttp-prod/bin/xray run -config /etc/slipnet-a1-xhttp-prod/server.json
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=384M
TasksMax=256
LimitNOFILE=16384
[Install]
WantedBy=multi-user.target
UNIT

runuser -u slipnet-a1-xhttp-prod -- /opt/slipnet-a1-xhttp-prod/bin/xray run -test -config /etc/slipnet-a1-xhttp-prod/server.json

systemctl daemon-reload
systemctl enable --now slipnet-a1-xhttp-prod.service
sleep 1
systemctl is-active --quiet slipnet-a1-xhttp-prod.service

if [[ "$FRONT_MODE" == coexist ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP="$CADDY_CFG.pre-slipnet-portable-$TS.bak"
  CANDIDATE="$(mktemp)"
  cp -a "$CADDY_CFG" "$BACKUP"
  python3 - "$CADDY_CFG" "$CANDIDATE" <<'PY'
import sys
src,dst=sys.argv[1:3]
begin="# BEGIN SLIPNET_PORTABLE_FOREIGN_PRODUCT"
end="# END SLIPNET_PORTABLE_FOREIGN_PRODUCT"
lines=open(src).read().splitlines()
out=[]
skip=False
for line in lines:
    if line.strip()==begin:
        skip=True
        continue
    if line.strip()==end:
        skip=False
        continue
    if not skip:
        out.append(line)
open(dst,"w").write("\n".join(out).rstrip()+"\n")
PY
  cat >>"$CANDIDATE" <<EOF

# BEGIN SLIPNET_PORTABLE_FOREIGN_PRODUCT
$PUBLIC_HOST {
    tls /etc/slipnet-portable-foreign/tls/fullchain.pem /etc/slipnet-portable-foreign/tls/privkey.pem
    @slipnet_portable_product {
        method GET POST
        path $PRODUCT_PATH/*
    }
    handle @slipnet_portable_product {
        request_body {
            max_size 131072
        }
        reverse_proxy 127.0.0.1:$PRODUCT_PORT {
            flush_interval -1
        }
    }
    handle {
        respond "not_found" 404
    }
}
# END SLIPNET_PORTABLE_FOREIGN_PRODUCT
EOF
  "$CADDY_BIN" validate --config "$CANDIDATE" --adapter caddyfile
  cp "$CANDIDATE" "$CADDY_CFG"
  rm -f "$CANDIDATE"

  if ! systemctl restart "$CADDY_UNIT"; then
    cp "$BACKUP" "$CADDY_CFG"
    systemctl restart "$CADDY_UNIT" || true
    echo "front restart failed; rolled back"
    exit 1
  fi
  sleep 1
  if ! systemctl is-active --quiet "$CADDY_UNIT"; then
    cp "$BACKUP" "$CADDY_CFG"
    systemctl restart "$CADDY_UNIT" || true
    echo "front unhealthy; rolled back"
    exit 1
  fi
  printf 'mode=coexist\nconfig=%s\nunit=%s\nbackup=%s\n' "$CADDY_CFG" "$CADDY_UNIT" "$BACKUP" >"$STATE/front-state"
else
  install -m 0755 "$P/caddy" /opt/slipnet-portable-foreign/bin/caddy
  cat >/etc/slipnet-portable-foreign/Caddyfile <<EOF
{
    auto_https disable_redirects
}
https://$PUBLIC_HOST {
    tls /etc/slipnet-portable-foreign/tls/fullchain.pem /etc/slipnet-portable-foreign/tls/privkey.pem
    @slipnet_portable_product {
        method GET POST
        path $PRODUCT_PATH/*
    }
    handle @slipnet_portable_product {
        request_body {
            max_size 131072
        }
        reverse_proxy 127.0.0.1:$PRODUCT_PORT {
            flush_interval -1
        }
    }
    handle {
        respond "not_found" 404
    }
}
EOF
  chown root:slipnet-foreign-caddy /etc/slipnet-portable-foreign/Caddyfile
  chmod 0640 /etc/slipnet-portable-foreign/Caddyfile

  cat >/etc/systemd/system/slipnet-portable-foreign-caddy.service <<'UNIT'
[Unit]
Description=SlipNet portable Foreign TLS front
After=network-online.target slipnet-a1-xhttp-prod.service
Requires=slipnet-a1-xhttp-prod.service
[Service]
Type=simple
User=slipnet-foreign-caddy
Group=slipnet-foreign-caddy
ExecStart=/opt/slipnet-portable-foreign/bin/caddy run --config /etc/slipnet-portable-foreign/Caddyfile --adapter caddyfile
ExecReload=/opt/slipnet-portable-foreign/bin/caddy reload --config /etc/slipnet-portable-foreign/Caddyfile --adapter caddyfile --force
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=256M
TasksMax=128
LimitNOFILE=16384
[Install]
WantedBy=multi-user.target
UNIT

  runuser -u slipnet-foreign-caddy -- /opt/slipnet-portable-foreign/bin/caddy validate --config /etc/slipnet-portable-foreign/Caddyfile --adapter caddyfile
  systemctl daemon-reload
  systemctl enable --now slipnet-portable-foreign-caddy.service
  printf 'mode=standalone\nconfig=/etc/slipnet-portable-foreign/Caddyfile\nunit=slipnet-portable-foreign-caddy.service\n' >"$STATE/front-state"
fi

chmod 0600 "$STATE/front-state"
"$BASE/validate.sh"
