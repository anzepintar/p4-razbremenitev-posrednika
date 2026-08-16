#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SUDO="${SUDO-sudo}"
MITM_SRC="${MITM_SRC:-$PWD/../../mitmproxy-quic-transparent}"
DERIVED="client:latest server:latest proxy:latest p4-switch:latest"

case "${1:-}" in
"") ;;
--clean | --clean-all)
	echo "== ciscenje =="
	for topo in A0 A1 B0 B1; do
		$SUDO clab destroy -t "../$topo.clab.yml" --cleanup >/dev/null 2>&1 || true
	done
	rm -rf out server/testset switch/build lists/*.txt lists/assignment.json \
		server/sites.caddy pki/trust.pem
	docker rmi -f $DERIVED >/dev/null 2>&1 || true
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	if [ "$1" = --clean-all ]; then
		docker rmi -f mitmproxy-quic:latest >/dev/null 2>&1 || true
		docker images -q 'bmv2-perf' | xargs -r docker rmi -f >/dev/null 2>&1 || true
	fi
	;;
*)
	echo "uporaba: rebuild.sh [--clean|--clean-all]" >&2
	exit 2
	;;
esac

[ -d "$MITM_SRC" ] || {
	echo "rebuild.sh: forka mitmproxy ni v '$MITM_SRC'; podaj pot z MITM_SRC" >&2
	exit 1
}

echo "== nabor testnih strani =="
if [ -d server/testset/testni ]; then
	echo "  ze zgrajen, preskocim"
else
	./build_testset.py
fi

echo "== seznami in razdelitev domen =="
./gen_lists.py

echo "== slike docker =="
MITM_SRC="$MITM_SRC" ./build.sh

echo "== enotski in integracijski testi =="
(cd .. && python3 -m pytest -m "not e2e" -q)
