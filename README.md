# P4 razbremenitev posrednika
Projekt preizkuša če lahko programabilno stikalo P4 razbremeni posrednik pri filtriranju šifriranega prometa.
Stikalo bmv2 iz prometa prebere ime strežnika, tako iz sporočila ClientHello pri TLS kot iz šifriranega paketa Initial pri QUIC.
Na tej podlagi promet blokira, spusti mimo ali pošlje posredniku mitmproxy, ki ga dešifrira in pregleda vsebino.
Okolje sestavi containerlab, primerja pa pet postavitev z različnimi potmi prometa.
Priloženi programi merijo zmogljivost, pravilnost politike in prag, pri katerem se stikalo izplača.
Vključena je veja mitmproxy s podporo za transparentno prestrezanje QUIC.
Pregled resničnega spleta obišče vzorec domen s curl, chromiumom in firefoxom.

Podrobnosti o postavitvah, gradnji in meritvah so v [testno_okolje/readme.md](testno_okolje/readme.md).

## Obvestilo
To je raziskovalni prototip, izdelan za namene ocene diplomske naloge.
Koda je bila napisana s pomočjo generativne umetne inteligence.
