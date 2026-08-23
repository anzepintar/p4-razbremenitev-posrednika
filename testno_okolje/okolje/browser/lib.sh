# Skupno za chromium.sh in firefox.sh.

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
