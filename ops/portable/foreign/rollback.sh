#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }
STATE=/var/lib/slipnet-portable-foreign/front-state
[[ -s "$STATE" ]] || { echo "no front state"; exit 1; }
source "$STATE"

if [[ "${mode:-}" == coexist ]]; then
  [[ -n "${backup:-}" && -f "$backup" ]] || { echo "backup missing"; exit 1; }
  cp "$backup" "$config"
  systemctl restart "$unit"
  systemctl is-active "$unit"
  echo "COEXIST_FRONT_ROLLED_BACK"
elif [[ "${mode:-}" == standalone ]]; then
  systemctl disable --now slipnet-portable-foreign-caddy.service || true
  echo "STANDALONE_FRONT_STOPPED"
else
  echo "unknown front mode"
  exit 1
fi

systemctl disable --now slipnet-a1-xhttp-prod.service || true
echo "PRODUCT_STOPPED"
