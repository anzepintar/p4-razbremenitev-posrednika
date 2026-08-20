#!/usr/bin/env bash
set -euo pipefail

PROFILE=/root/.mozilla/diploma
mkdir -p "$PROFILE"

: >"$PROFILE/user.js"
if [ -n "${FORCE_QUIC:-}" ]; then
	case "$FORCE_QUIC" in
	all | '*')
		echo "firefox.sh: FORCE_QUIC=all ni mogoc, firefox rabi domeno" >&2
		exit 2
		;;
	esac
	{
		echo 'user_pref("network.http.http3.enable", true);'
		printf 'user_pref("network.http.http3.alt-svc-mapping-for-testing", "%s;h3=:443");\n' \
			"$FORCE_QUIC"
		echo 'user_pref("network.http.http3.force-use-alt-svc-mapping-for-testing", true);'
	} >"$PROFILE/user.js"
fi

exec firefox --no-remote --profile "$PROFILE" "$@"
