#!/usr/bin/env bash
set -euo pipefail

CERT=/opt/traffic/pki/trust.pem
NICK=diploma-mitm
DB=sql:/root/.pki/nssdb

[ -s "$CERT" ] || {
	echo "trust_nss.sh: $CERT je prazen; ali posrednik ze tece?" >&2
	exit 1
}

install -D -m 644 "$CERT" /usr/local/share/ca-certificates/$NICK.crt
update-ca-certificates >/dev/null

mkdir -p /root/.pki/nssdb
[ -s /root/.pki/nssdb/cert9.db ] || certutil -d "$DB" -N --empty-password
certutil -D -d "$DB" -n "$NICK" 2>/dev/null || true
certutil -A -d "$DB" -n "$NICK" -t C,, -i "$CERT"

certutil -L -d "$DB" | grep "$NICK"
