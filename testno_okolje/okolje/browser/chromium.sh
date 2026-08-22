#!/usr/bin/env bash
set -euo pipefail

# Zastavice so na enem mestu, ker jih poleg namizja uporablja tudi pregled spleta
# (probe/clients.py). Nastavljajo se prek okolja, da se slike ni treba graditi znova.
#
#   FORCE_QUIC=<gostitelj>|all  vsili h3 za ta izvor (brez vrat, doda se :443)
#   NO_QUIC=1                   izklopi QUIC, torej h2 ali starejse
#   USER_DATA_DIR=<pot>         svoj profil; pregled ga da za vsako domeno novega,
#                               da se alt-svc ne prenasa med protokoloma

# Pravilnik se namesti ob vsakem zagonu, zato ga je mogoce spremeniti brez ponovne
# gradnje slike, tako kot zastavice. Pregled zaganja vec brskalnikov hkrati, zato gre
# zapis prek zacasne datoteke in preimenovanja; ce je vsebina ze prava, se ne zgodi nic.
install_policy() {
	local src="$1" dst="$2" tmp
	[ -f "$src" ] || return 0
	cmp -s "$src" "$dst" 2>/dev/null && return 0
	mkdir -p "$(dirname "$dst")"
	tmp=$(mktemp "$(dirname "$dst")/.policy.XXXXXX") || return 0
	if cat "$src" >"$tmp" && chmod 644 "$tmp"; then
		mv -f "$tmp" "$dst"
	else
		rm -f "$tmp"
	fi
}

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
