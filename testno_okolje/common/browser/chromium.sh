#!/usr/bin/env bash
set -euo pipefail

QUIC=()
if [ -n "${FORCE_QUIC:-}" ]; then
	case "$FORCE_QUIC" in
	all | '*') QUIC=(--origin-to-force-quic-on='*') ;;
	*) QUIC=(--origin-to-force-quic-on="$FORCE_QUIC:443") ;;
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
	--user-data-dir=/root/.chromium \
	--enable-quic \
	--start-maximized \
	"${QUIC[@]}" \
	"$@"
