#!/usr/bin/env bash
#   ./subset.sh <osnovni|testni>
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SET="${1:?uporaba: subset.sh <osnovni|testni>}"

[ -d "server/testset/$SET" ] || {
	echo "subset.sh: nabora '$SET' ni v server/testset - pozeni build_testset.py" >&2
	exit 2
}

sed -i -E "s|^( *set:) *[A-Za-z0-9_-]+|\1 $SET|" scenario.yml
grep -qE "^ *set: *$SET\b" scenario.yml || {
	echo "subset.sh: nastavitev nabora v scenario.yml ni uspela" >&2
	exit 1
}

python3 gen_caddyfile.py
python3 gen_lists.py

echo "subset.sh: nabor '$SET' ($(find "server/testset/$SET" -maxdepth 1 -mindepth 1 -type d | wc -l) domen)"
