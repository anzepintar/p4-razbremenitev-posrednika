#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SUDO="${SUDO-sudo}"
OWNER="${SUDO_USER:-$(id -un)}"

[ -n "$(find okolje ! -user "$OWNER" -print -quit 2>/dev/null)" ] || exit 0

echo "reclaim: v okolje/ so datoteke, ki niso od $OWNER, ker vsebniki pisejo v priklop; prevzemam"
$SUDO chown -R "$OWNER:$(id -gn "$OWNER")" okolje
