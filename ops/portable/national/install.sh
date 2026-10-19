#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="$BASE/payload"
[[ -d "$P" ]] || { echo "payload missing"; exit 1; }
cd "$BASE"
sha256sum -c SHA256SUMS
source "$P/meta.env"

for x in systemctl python3 openssl ss nft curl ip; do command -v "$x" >/dev/null || { echo "missing dependency: $x"; exit 1; }; done

if ss -H -lnt "sport = :443" | grep -q .; then
  if ! systemctl is-active --quiet slipnet-a1-cdn-gateway.service 2>/dev/null; then
    echo "port 443 already occupied by an unknown service; aborting"
    ss -lntp "sport = :443" || true
    exit 1
  fi
fi

id -u slipnet-a1-xhttp-prod >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin slipnet-a1-xhttp-prod
id -u slipnet-a1-cdn-gateway >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin slipnet-a1-cdn-gateway

install -d -m 0755 /opt/slipnet-portable-national/bin
install -d -m 0750 -o root -g slipnet-a1-xhttp-prod /etc/slipnet-a1-xhttp-prod
install -d -m 0750 -o root -g slipnet-a1-cdn-gateway /etc/slipnet-a1-cdn-gateway/tls
install -d -m 0700 /var/lib/slipnet-arvan-guard

install -m 0755 "$P/xray" /opt/slipnet-portable-national/bin/xray
install -m 0640 -o root -g slipnet-a1-xhttp-prod "$P/product-client.json" /etc/slipnet-a1-xhttp-prod/client-edge234.json
install -m 0640 -o root -g slipnet-a1-cdn-gateway "$P/gateway.json" /etc/slipnet-a1-cdn-gateway/server.json
install -m 0644 -o root -g slipnet-a1-cdn-gateway "$P/tls/fullchain.pem" /etc/slipnet-a1-cdn-gateway/tls/fullchain.pem
install -m 0640 -o root -g slipnet-a1-cdn-gateway "$P/tls/privkey.pem" /etc/slipnet-a1-cdn-gateway/tls/privkey.pem
install -m 0700 "$P/guard/update" /usr/local/sbin/slipnet-arvan-allowlist-update
install -m 0700 "$P/guard/restore" /usr/local/sbin/slipnet-arvan-allowlist-restore
[[ -s "$P/guard/rules.nft" ]] && install -m 0600 "$P/guard/rules.nft" /var/lib/slipnet-arvan-guard/rules.nft
[[ -s "$P/guard/ips.txt" ]] && install -m 0600 "$P/guard/ips.txt" /var/lib/slipnet-arvan-guard/ips.txt

cat >/etc/systemd/system/slipnet-a1-xhttp-prod-client.service <<'UNIT'
[Unit]
Description=SlipNet portable National XHTTP product client
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=slipnet-a1-xhttp-prod
Group=slipnet-a1-xhttp-prod
ExecStart=/opt/slipnet-portable-national/bin/xray run -config /etc/slipnet-a1-xhttp-prod/client-edge234.json
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

cat >/etc/systemd/system/slipnet-portable-return-route.service <<'UNIT'
[Unit]
Description=SlipNet National CDN return-route rule
Before=slipnet-a1-cdn-gateway.service
After=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'while ip -4 rule del priority 10012 2>/dev/null; do :; done; ip -4 rule add priority 10012 ipproto tcp sport 443 lookup main'
ExecStop=/bin/sh -c 'while ip -4 rule del priority 10012 2>/dev/null; do :; done'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/slipnet-arvan-allowlist-restore.service <<'UNIT'
[Unit]
Description=Restore cached Arvan CDN allowlist before SlipNet Gateway
Before=slipnet-a1-cdn-gateway.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/slipnet-arvan-allowlist-restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/slipnet-arvan-allowlist-update.service <<'UNIT'
[Unit]
Description=Update SlipNet Arvan CDN origin allowlist
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/slipnet-arvan-allowlist-update
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/slipnet-arvan-guard
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
UNIT

cat >/etc/systemd/system/slipnet-arvan-allowlist-update.timer <<'UNIT'
[Unit]
Description=Refresh SlipNet Arvan CDN origin allowlist
[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true
[Install]
WantedBy=timers.target
UNIT

cat >/etc/systemd/system/slipnet-a1-cdn-gateway.service <<'UNIT'
[Unit]
Description=SlipNet portable National CDN Gateway
After=network-online.target slipnet-a1-xhttp-prod-client.service slipnet-arvan-allowlist-restore.service slipnet-portable-return-route.service
Requires=slipnet-a1-xhttp-prod-client.service slipnet-arvan-allowlist-restore.service slipnet-portable-return-route.service
[Service]
Type=simple
User=slipnet-a1-cdn-gateway
Group=slipnet-a1-cdn-gateway
ExecStart=/opt/slipnet-portable-national/bin/xray run -config /etc/slipnet-a1-cdn-gateway/server.json
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
UMask=0077
MemoryMax=384M
TasksMax=256
LimitNOFILE=16384
[Install]
WantedBy=multi-user.target
UNIT

runuser -u slipnet-a1-xhttp-prod -- /opt/slipnet-portable-national/bin/xray run -test -config /etc/slipnet-a1-xhttp-prod/client-edge234.json
runuser -u slipnet-a1-cdn-gateway -- /opt/slipnet-portable-national/bin/xray run -test -config /etc/slipnet-a1-cdn-gateway/server.json

systemctl daemon-reload
systemctl enable --now slipnet-portable-return-route.service
systemctl enable --now slipnet-arvan-allowlist-restore.service
systemctl enable --now slipnet-arvan-allowlist-update.timer
systemctl start slipnet-arvan-allowlist-update.service || true
systemctl enable --now slipnet-a1-xhttp-prod-client.service
systemctl enable --now slipnet-a1-cdn-gateway.service
sleep 1
"$BASE/validate.sh"
