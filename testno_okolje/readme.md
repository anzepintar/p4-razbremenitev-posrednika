# Testno okolje

## Postavitve

Štiri postavitve po dveh oseh: s stikalom P4 ali brez njega, ter proti lokalnemu strežniku
s testnim naborom ali proti pravemu spletu prek prehoda.

| postavitev | pot | namen |
| :--- | :--- | :--- |
| `A0` | client — mitm — server | meritev: ves promet prek posrednika |
| `B0` | client — p4 — mitm — server | meritev: P4 razbremeni posrednika po naslovu in domeni |
| `A1` | client — mitm — gateway → splet | ročno testiranje na resničnih straneh |
| `B1` | client — p4 — mitm — gateway → splet | ročno testiranje na resničnih straneh |

```
A0 / A1        B0 / B1

client -- mitm -- server|gateway   client -- p4 -- server|gateway
                                              |
                                             mitm
```

Posrednik teče v **transparentnem** načinu (`--mode transparent@8080`): QUIC (UDP/443)
prestreže prek TPROXY, TCP/443 pa prek `REDIRECT` in `SO_ORIGINAL_DST`. Prestrezanje
QUIC-a doda fork mitmproxy iz `mitmproxy-quic-transparent`.

Pri postavitvah s stikalom vnose v tabeli `ip_policy` in `sni_policy` ob zagonu zapiše
`common/proxy/steer.py`, ki teče v vsebniku posrednika in se prek P4Runtime
(gRPC 10.20.1.2:9559) poveže na stikalo. Ločenega krmilnika ni.

## Politika

Stikalo odloča v tem vrstnem redu:

| pogoj | izid |
| :--- | :--- |
| ni IPv4, ali TTL ≤ 1 | zavrže |
| ni TCP in ni UDP/443 (izjemi DNS in ICMP) | zavrže |
| ciljni naslov na črnem seznamu IP | zavrže |
| ciljni naslov na belem seznamu IP | direktno na strežnik oziroma v splet |
| UDP/443 od odjemalca | posrednik |
| SNI na črnem seznamu domen | zavrže |
| vse ostalo | posrednik |

Posrednik nato pregleda, kar je dobil:

| promet | ravnanje |
| :--- | :--- |
| domena na belem seznamu | surov tunel, brez dešifriranja |
| domena na črnem seznamu | prekine sejo (`sni_block.py`) — tako je pokrit QUIC |
| ostalo | dešifrira in preveri vsebino (`content_block.py`) |

## Seznami

Vse štiri sezname urejaš neposredno v `common/lists/`:

| datoteka | pomen |
| :--- | :--- |
| `domain_black.txt` | domene, ki jih zavrže stikalo (TCP) oziroma posrednik (QUIC) |
| `domain_white.txt` | domene, ki jih posrednik le tunelira in ne dešifrira |
| `ip_black.txt` | naslovi, ki jih stikalo zavrže že ob paketu SYN |
| `ip_white.txt` | naslovi, ki gredo mimo posrednika |

Ena postavka na vrstico, `#` je opomba, prazne vrstice se preskočijo. V datotekah domen velja
vzorec z začetno piko za vse poddomene (`.primer.com` ujame `a.primer.com`, ne pa `primer.com`).
V datotekah naslovov lahko napišeš naslov, predpono CIDR ali domeno — ta se razreši v IPv4 ob
zagonu. Ista postavka na črnem in belem seznamu je napaka.

`common/gen_lists.py` datoteke prednapolni: v `domain_black.txt` zapiše vse domene z oznako
`mal` iz trenutnega nabora, v `domain_white.txt` pa `anzepintar.com` in `quic.anzepintar.com`.
Obstoječih datotek
ne povozi, zato tvoje spremembe preživijo `subset.sh`; z `--force` jih zapiše na novo, z
`--white-share 0.3` v beli seznam doda še tretjino domen `ben`. Ob vsakem zagonu izpiše, koliko
domen `mal` iz nabora je na črnem seznamu in koliko postavk v naboru ni.

```sh
./common/gen_lists.py                       # prednapolni, kar manjka
./common/gen_lists.py --force               # zapiši vse na novo iz nabora
```

Naslova se preverita že ob paketu SYN, zato veljata za TCP in QUIC hkrati. Ves testni nabor stoji
na enem naslovu (`testset.ip`, privzeto `10.0.2.10`), zato je pravilo IP v A0 in B0 vse ali nič —
ločevanje po naslovu je smiselno šele proti pravemu spletu, v A1 in B1.

## Meje politike

Dvoje je vredno vedeti, ker izhaja iz zgradbe protokolov in ne iz izbire:

**Bela domena ni obvod po žici.** Pot se izbere ob paketu SYN, SNI pa je na žici šele po
vzpostavitvi seje — ko stikalo vidi ime, je seja že vzpostavljena s posrednikom in je ni
mogoče prevezati. Zato belo domeno uveljavi posrednik kot surov tunel: brez dešifriranja in
brez potrdila, a paketi še vedno tečejo skozi njegov vmesnik. Pravi obvod je le `ip_white.txt`,
ker je naslov znan že ob SYN.

**QUIC gre vedno na posrednika.** Ključi za paket Initial se po RFC 9001 izpeljejo iz
konstantne soli in DCID, kar terja HKDF in AES-GCM; teh primitiv v BMv2 ni, zato stikalo SNI
v h3 ne more prebrati. Črni seznam za QUIC zato uveljavi posrednik.

Izjema za DNS in ICMP je nujna: v B1 gre skozi cevovod tudi posrednikov lastni DNS, brez nje
se ne razreši nobeno ime.

Meje: prikrivanje domene (`fronting`) v SNI pokaže neškodljivo krinko, zato ga ujame šele
posrednik prek glave Host. Ime, daljše od 63 bajtov, in SNI za več kot šestimi razširitvami se
ne prepoznata. Števce prebere `measure.sh` v `switch_sni.json`.

## En odjemalec ali trije

**Trenutno je nastavljen en sam odjemalec** (`10.0.1.10`), ker `curl` brez `--interface` vedno
vzame prvi naslov na `eth1` in je bilo pri ročnem testiranju nejasno, kateri odjemalec je
pravzaprav poslal zahtevo. Pred meritvijo za nalogo vrni vse tri.

Vrnitev: v vsako od `A0/A1/B0/B1.clab.yml` pri vozlišču `client` dodaj nazaj

```yaml
        - ip addr add 10.0.1.11/24 dev eth1
        - ip addr add 10.0.1.12/24 dev eth1
```

v `common/scenario.yml` pa zbriši začasno vrstico in odkomentiraj izvirne tri, ki so tam že
pripravljene.

Profili so vsi trije ostali v `scenario.yml`, zato je vrnitev le prepis teh dveh mest.

Kar medtem odpade: prikrivanje domene (`fronting`), ker ga ima le profil `suspicious`.

Vrata bmv2 so fiksna: 1 = odjemalec, 2 = strežnik oziroma prehod, 3 = posrednik. `eth4`
stikala je le upravljalna pot do posrednika in ni del cevovoda P4.

## Namestitev

Vsi ukazi tečejo iz imenika testno_okolje. Gradnja potrebuje fork mitmproxy; privzeto ga
išče v `../mitmproxy-quic-transparent`, drugo pot podaš z `MITM_SRC`.

```sh
./common/build_testset.py
./common/gen_lists.py
./common/build.sh
```

Sliko forka gradi `common/proxy/mitmproxy.Dockerfile`, kontekst gradnje pa je izvorna koda
forka (`MITM_SRC`), ne imenik `common`. Slika `mitmproxy-quic:latest` se zgradi le, če je še
ni. Po spremembi forka:

```sh
docker rmi mitmproxy-quic:latest && ./common/build.sh
```

## Nabor testnih primerov

```sh
./common/subset.sh osnovni
./common/subset.sh testni
```

## Meritev latence in hitrosti

Merljivi sta postavitvi s strežnikom, ker runner potrebuje lokalni testni nabor.

```sh
./common/measure.sh latency "A0 B0" 40 # zahtev na odjemalni IP
./common/measure.sh latency "A0 B0" 40 --content-block
```

## Meritev nasičenja

```sh
./common/measure.sh ramp "A0 B0" "1 2 4 8 16"
./common/measure.sh ramp "A0 B0" "1 2 4 8 16" --content-block
```

## Grafi in rezultati

```sh
./common/plot.py
```

## Ročno testiranje na spletu

```sh
./common/start.sh B1
docker exec clab-B1-client \
curl --http3-only	--cacert /opt/traffic/pki/trust.pem https://quic.anzepintar.com/
sudo clab destroy -t B1.clab.yml --cleanup
```

Kontrolno zahtevo ob zagonu nastaviš s `PROBE_URL`. Prestrežene zahteve so v
`common/out/proxy_flows.jsonl`, dnevnik posrednika v `common/out/mitm.log`.

## Spletni vmesnik posrednika

Privzeto teče `mitmdump`, ki vmesnika nima. Z `--web` namesto njega steče `mitmweb`:

```sh
./common/start.sh B1 --web
```

`start.sh` na koncu izpiše naslov oblike `http://172.20.20.3:8081/?token=diploma`; brez
`?token=` vrne 403. Geslo zamenjaš z `WEB_PASSWORD`. Za merjeni postavitvi A0 in B0 pusti
`mitmdump`, ker vmesnik doda režijo.

## Zagon brez sudo

```sh
SUDO= common/measure.sh latency A0 40
SUDO= common/start.sh B0
```

## Ročni zagon postavitve

```sh
./common/start.sh B0 --content-block
sudo clab destroy -t B0.clab.yml --cleanup
```

## Čiščenje

```sh
rm -rf common/out/*
rm -f common/pki/trust.pem
```
