#!/usr/bin/env bash
set -euo pipefail

# Zastavice so na enem mestu, ker jih poleg namizja uporablja tudi pregled spleta
# (probe/clients.py). Nastavljajo se prek okolja, da se slike ni treba graditi znova.
#
#   FORCE_QUIC=<gostitelj>|all  vsili h3 za ta izvor (brez vrat, doda se :443)
#   NO_QUIC=1                   izklopi QUIC, torej h2 ali starejse
#   USER_DATA_DIR=<pot>         svoj profil; pregled ga da za vsako domeno novega,
#                               da se alt-svc ne prenasa med protokoloma

# shellcheck source=okolje/browser/lib.sh
. /opt/traffic/browser/lib.sh

install_policy /opt/traffic/browser/policies/chromium.json \
	/etc/chromium/policies/managed/diploma.json

QUIC=(--enable-quic)
if [ "${NO_QUIC:-}" = 1 ]; then
	QUIC=(--disable-quic)
elif [ -n "${FORCE_QUIC:-}" ]; then
	case "$FORCE_QUIC" in
	all | '*') QUIC+=(--origin-to-force-quic-on='*') ;;
	*) QUIC+=(--origin-to-force-quic-on="$FORCE_QUIC:443") ;;
	esac
fi

exec chromium \
	--no-sandbox \
	--disable-gpu \
	--password-store=basic \
	--no-first-run \
	--no-default-browser-check \
	--disable-features=EncryptedClientHello \
	--disable-background-networking \
	--disable-component-update \
	--disable-sync \
	--disable-domain-reliability \
	--disable-client-side-phishing-detection \
	--user-data-dir="${USER_DATA_DIR:-/root/.chromium}" \
	--start-maximized \
	"${QUIC[@]}" \
	"$@"
