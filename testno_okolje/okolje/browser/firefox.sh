#!/usr/bin/env bash
set -euo pipefail

# Kot chromium.sh: iste zastavice za namizje in za pregled spleta, nastavljene prek
# okolja.
#
#   FORCE_QUIC=<gostitelj>[,<gostitelj>...]  vsili h3 za nastete gostitelje
#   NO_QUIC=1                                izklopi h3
#   PROFILE_DIR=<pot>                        svoj profil
#   MARIONETTE_PORT=<vrata>                  vrata za daljinski protokol, hkrati vklopi
#                                            nastavitve za pregled (brez ozadnega prometa)
#   NO_KYBER=1                               brez hibridnega kljuca, zato gre ClientHello
#                                            v en datagram (diagnostika, glej readme)
#
# Vsiljeni h3 velja za tocno ime gostitelja: preslikava za apex domeno ne velja vec,
# ko stran preusmeri na www, zato pregled vanjo vpise koncne gostitelje.

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

# Firefox bere obe poti, zato gre pravilnik v obe.
POLICY=/opt/traffic/browser/policies/firefox.json
install_policy "$POLICY" /etc/firefox-esr/policies/policies.json
install_policy "$POLICY" /usr/lib/firefox-esr/distribution/policies.json

PROFILE="${PROFILE_DIR:-/root/.mozilla/diploma}"
mkdir -p "$PROFILE"

alt_svc() {
	printf '%s' "$1" | tr ',' '\n' | sed '/^[[:space:]]*$/d' |
		sed 's/[[:space:]]//g; s/$/;h3=\\":443\\"/' | paste -sd,
}

{
	if [ -n "${MARIONETTE_PORT:-}" ]; then
		printf 'user_pref("marionette.port", %s);\n' "$MARIONETTE_PORT"
		echo 'user_pref("browser.shell.checkDefaultBrowser", false);'
	fi

	if [ "${MARIONETTE_PORT:-}" ]; then
		# Pregled meri stran, ne firefoxa: brez teh nastavitev se v stevce stikala in
		# v dnevnik posrednika prilije se firefoxov lasten promet do storitev Mozille,
		# ki je bil izmerjen v tisocih zahtev na blok.
		echo 'user_pref("app.update.enabled", false);'
		echo 'user_pref("app.normandy.enabled", false);'
		echo 'user_pref("browser.safebrowsing.malware.enabled", false);'
		echo 'user_pref("browser.safebrowsing.phishing.enabled", false);'
		echo 'user_pref("browser.safebrowsing.downloads.enabled", false);'
		echo 'user_pref("datareporting.healthreport.uploadEnabled", false);'
		echo 'user_pref("security.remote_settings.crlite_filters.enabled", false);'
		echo 'user_pref("security.remote_settings.intermediates.enabled", false);'
		echo 'user_pref("extensions.systemAddon.update.enabled", false);'
		echo 'user_pref("network.http.speculative-parallel-limit", 0);'
	fi

	if [ "${NO_KYBER:-}" = 1 ]; then
		echo 'user_pref("security.tls.enable_kyber", false);'
		echo 'user_pref("network.http.http3.enable_kyber", false);'
	fi

	if [ "${NO_QUIC:-}" = 1 ]; then
		echo 'user_pref("network.http.http3.enable", false);'
	elif [ -n "${FORCE_QUIC:-}" ]; then
		case "$FORCE_QUIC" in
		all | '*')
			echo "firefox.sh: FORCE_QUIC=all ni mogoc, firefox rabi imena gostiteljev" >&2
			exit 2
			;;
		esac
		echo 'user_pref("network.http.http3.enable", true);'
		printf 'user_pref("network.http.http3.alt-svc-mapping-for-testing", "%s");\n' \
			"$(alt_svc "$FORCE_QUIC")"
		echo 'user_pref("network.http.http3.force-use-alt-svc-mapping-for-testing", true);'
	fi
} >"$PROFILE/user.js"

exec firefox --no-remote --profile "$PROFILE" "$@"
