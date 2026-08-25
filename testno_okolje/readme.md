# Testno okolje

Primerjava dveh rešitev za filtriranje šifriranega prometa ob eni sami neodvisni
spremenljivki, prisotnosti stikala. Vsi ukazi tečejo iz imenika `testno_okolje`.

Imenik `okolje/` je tisto, kar vsak vsebnik vidi kot `/opt/traffic`; `orodja/` so
gostiteljske skripte, ki jih poganjaš sam.

## Postavitve

| postavitev | pot | namen |
| :--- | :--- | :--- |
| `C0` | odjemalec — strežnik | referenca: kaj zmore merilna oprema sama |
| `A0` | odjemalec — posrednik — strežnik | meritev: ves promet prek posrednika |
| `B0` | odjemalec — stikalo — posrednik — strežnik | meritev: stikalo razbremeni posrednika |
| `B1` | odjemalec — stikalo — posrednik — prehod → splet | pregled pravega spleta in brskalnik |
| `C1` | odjemalec — prehod → splet | izhodišče za `B1` |

Posrednik teče v načinu `--mode transparent@8080`: QUIC (UDP/443) prestreže prek TPROXY,
TCP/443 pa prek `REDIRECT`. Tabeli `ip_policy` in `sni_policy` ob zagonu napolni
`okolje/proxy/steer.py` prek P4Runtime (gRPC 10.20.1.2:9559). Vrata bmv2 so fiksna:
1 = odjemalec, 2 = strežnik oziroma prehod, 3 = posrednik.

## Gradnja

Potrebuješ `docker`, `containerlab` in vejo mitmproxy; privzeto se išče v
`../mitmproxy-quic-transparent`, drugo pot podaš z `MITM_SRC`.

```sh
./orodja/rebuild.sh          # nabor, seznami, slike, testi; vse od zacetka

./orodja/build_testset.py    # samo nabor strani iz LNU-Phish (132 MB, 1002 domeni)
./orodja/gen_lists.py        # samo seznami in razdelitev domen iz experiment.yml
./orodja/build.sh            # samo slike docker
```

Sliki `mitmproxy-quic:latest` in `browser:latest` ter `bmv2-perf:1.15.5-modules` se zgradijo
le, če jih še ni, zato je po spremembi veje mitmproxy oziroma `okolje/client/Dockerfile`
potreben `docker rmi mitmproxy-quic:latest browser:latest && ./orodja/build.sh`. Po spremembi
`quic_sni.cpp`, `quic_extern.cpp` ali `steering.p4` zadošča `./orodja/build.sh`.

## Nastavitev

Vse nastavlja `okolje/experiment.yml`, edina datoteka, ki jo urejaš; iz nje se izpeljejo
seznami, razdelitev domen, naslovi strežnika in matrika meritve.

| ključ | kaj določa |
| :--- | :--- |
| `domains.total`, `domains.groups` | koliko domen gre v meritev in kako se razdelijo po skupinah |
| `server_ips` | privzeti naslov strežnika ter ločena naslova za `ip_black` in `ip_white` |
| `protocols` | delež zahtev po HTTP/2 in HTTP/3 |
| `modes` | katere skupine prometa se merijo |
| `load` | izteka `connect_timeout_s` in `max_time_s`, velikost objekta `object_kb` |
| `run` | seme, izhodni imenik, korensko potrdilo in nabor strani |

Vsak način iz `modes` potrebuje svojo skupino domen, vsota skupin pa ne sme preseči `total`.
Razdelitev je determinstična (sha1 imena domene). Po vsaki spremembi poženi
`./orodja/gen_lists.py`; datotek v `okolje/lists/` ne urejaj ročno, ker jih prepiše.

| skupina prometa | ključ | mehanizem | v `A0` | v `B0` |
| :--- | :--- | :--- | :--- | :--- |
| črni IP promet | `ip_black` | naslov `10.0.2.11` | posrednik (`--block-list`) | stikalo, ob prvem paketu |
| beli IP promet | `ip_white` | naslov `10.0.2.12` | posrednik tunelira (`--ignore-hosts`) | stikalo, mimo posrednika |
| črni domenski promet | `sni_black` | `domain_black.txt` | posrednik (`--block-list`) | stikalo, ob `ClientHello` oziroma `Initial` |
| beli domenski promet | `sni_white` | `domain_white.txt` | posrednik tunelira | TCP: posrednik tunelira; QUIC: stikalo, mimo posrednika |
| promet, blokiran po vsebini | `content_block` | `content_rules.txt` | posrednik, po dešifriranju | posrednik, po dešifriranju |
| ostali promet | `unknown` | — | dešifrira se | dešifrira se |

Ta imena so v veljavi povsod, na grafih, v tabelah in v besedilu. Način `other` v `modes` je
ista skupina kot `unknown`, torej ostali promet.

Dodatek `content_block.py` je privzeto vklopljen, ker ga meritev potrebuje; izklopi ga
`--no-content-block`. Pri `object_kb > 0` odjemalec namesto dokumenta strani potegne
`/big.bin` te velikosti.

## Stikalo

Ime strežnika iz prometa TCP razčleni razčlenjevalnik v `okolje/switch/steering.p4`, iz
šifriranega paketa `Initial` pa ga prebere zunanja funkcija bmv2
`okolje/switch/quic_sni.cpp`; obe poti pišeta v `meta.sni` in vprašata isto tabelo
`sni_policy`. Modul se naloži z `--load-modules` v `start_switch.sh`, zato je potrebna slika
`bmv2-perf:1.15.5-modules`, prevedena z `-rdynamic`. Meje so konstante v `steering.p4`:
`MAX_SNI_NAME` 63, `MAX_EXT_BODY` 256, `QUIC_TIMEOUT_MS` 60000, `QUIC_MAX_FLOWS` 65536 in
`QUIC_MAX_CRYPTO` 16384.

## Meritve

| program | postavitev | kaj pove |
| :--- | :--- | :--- |
| `./orodja/m1_oprema.sh` | `C0` | zgornja meja merilne opreme same, oba protokola |
| `./orodja/m2_stikalo.sh` | `A0`, `B0` | cena prestrezanja in cena stikala v poti |
| `./orodja/m3_pravilnost.sh` | `A0`, `B0` | pravilnost uveljavljanja politike |
| `./orodja/m4_vrste.sh` | `A0`, `B0` | vpliv stikala po posameznih skupinah prometa |
| `./orodja/m5_zmogljivost.sh` | `A0`, `B0` | največja hitrost za skupine, ki gredo lahko čez |
| `./orodja/m6_prag.sh` | `A0`, `B0` | delež obhoda, pri katerem je stikalo smiselno |

Vsak program zapiše v `okolje/out/<ime>/` sliko v `graf/`, `results.md`, `veljavnost.md` in
`results.json`; nariše jih `./orodja/plot.py okolje/out/<ime>`, ki ga pokličejo sami.
`m1`, `m2` in `m5` iščejo največjo vzdržno hitrost brez izgube (podvajanje, nato bisekcija,
na koncu potrditveni tek), `m4` in `m6` pa merita pri stalni obremenitvi `RATE_H2` oziroma
`RATE_H3`. Ta je izbrana pod maksimumoma iz `m2`. Če ni, program to izpiše kot opozorilo.

| spremenljivka | privzeto | kaj je |
| :--- | :--- | :--- |
| `DURATION`, `WARMUP` | 20, 0 | trajanje celice in odbitek na začetku v sekundah |
| `WARMUP_REQUESTS` | 100, v `m4` in `m6` 300 | zahteve ogrevalnega teka pred celico |
| `SEARCH_START`, `SEARCH_MAX`, `SEARCH_TOLERANCE` | 8, 512, 5 | meji iskanja in razmik bisekcije |
| `RATE_H2`, `RATE_H3` | 80, 10 | stalna obremenitev v `m4` in `m6` v zahtevah/s |
| `CELL_MODES` | `other ip_white sni_white` | skupine prometa v `m5` |
| `MECHANISMS`, `SHARES` | `ip_white sni_white`, `0 25 50 75 100` | skupini prometa in deleži obhoda v `m6` |
| `SUDO` | `sudo` | prazno, kadar `clab` ne potrebuje pravic |

## Pregled spleta

Pregled najprej iz izvoza Cloudflare Radarja izbere nabor, nato iz njega vzame vzorec
stotih domen in ga obišče s curl, chromium in firefox, vsakega po HTTP/2 in HTTP/3. Vzorec
je iz domen, ki delujejo po obeh protokolih, in ga določa seme, zato vsi bloki obeh
postavitev vidijo iste domene.

```sh
./orodja/splet.sh                  # izbor in pregled vzorca stotih domen
LIMIT=5 SWEEP_CLIENTS=curl ./orodja/splet.sh

./orodja/splet_nabor.sh            # samo izbor, za pogled v osip nabora
SELECT_LIMIT=20 ./orodja/splet_nabor.sh
```

Datotek ne urejaj med tekom. Lupina skripto bere sproti, zato bi jo urejanje na mestu
pokvarilo sredi teka; oba programa imata potek v funkciji `main`, kar to prepreči.

Izbor je del pregleda in teče v isti postavitvi `C1`, z istimi izteki in istim merilom, zato
med izborom in meritvijo ni odstopanj. Ima dva koraka. Prvi poišče končnega gostitelja
domene, pri čemer ob neuspehu poskusi še predpono `www`. Drugi pri vsakem dosegljivem
gostitelju preveri oba protokola. Izid je `okolje/splet_nabor.json`, kopija pa ostane pri
rezultatih teka. Program `splet_nabor.sh` opravi isti izbor sam zase, kadar te zanima le
osip nabora.

| spremenljivka | privzeto | kaj je |
| :--- | :--- | :--- |
| `CSV` | `../testni_podatki/cloudflare-radar_top-1000-domains_20260701-20260731.csv` | izvoz domen |
| `NABOR` | `okolje/splet_nabor.json` | kam se zapiše izbrani nabor |
| `SWEEP_CLIENTS`, `SWEEP_PROTOS` | `curl chromium firefox`, `h2 h3` | kaj se pregleda |
| `SAMPLE`, `SEED` | 100, 1234 | velikost vzorca pregleda (0 je cel nabor) in seme |
| `SELECT_LIMIT`, `SELECT_JOBS` | 0, 64 | koliko domen gre v izbor (0 je vse) in vzporednost izbora |
| `LIMIT`, `RETRIES`, `KEEP` | 0, 1, 1 | koliko domen vzorca (0 je vse), ponovitve, pusti `B1` pokoncno |
| `CONNECT_TIMEOUT`, `MAX_TIME` | 10, 10 | izteka curl v sekundah, ista pri izboru in pregledu |
| `PAGE_TIMEOUT` | 15 | iztek brskalnika v sekundah |
| `NO_KYBER` | 0 | firefoxu vzame hibridni ključ; diagnostika, ne meritev |

Izbor pusti ob naboru še `apex.json`, kjer so z razlogom tudi domene, ki so iz nabora
izpadle. Izhod pregleda je v `okolje/out/splet/`: `results.md` (izbor,
delovanje strani, strani samo po HTTP/2 in razsodbe stikala), `nedelujoce.md` (samo strani,
ki delujejo v `C1` in ne v `B1`), `results.json`, `nabor.json` in
`<postavitev>/probes_<odjemalec>_<protokol>.jsonl`.

## Testi

| nivo | kaj potrebuje | koliko |
| :--- | :--- | ---: |
| `unit` | samo Python | 181 |
| `integration` | bere `steering.p4`, za QUIC še sliko `p4-switch` | 27 |
| `e2e` | tekočo postavitev `B0` | 31 |

```sh
python3 -m pytest                 # vse; e2e se preskoci brez postavitve
python3 -m pytest -m "not e2e"    # brez vsebnikov
python3 -m pytest -m e2e          # sele po ./orodja/start.sh B0

docker run --rm -v "$PWD/tests/data:/out" --entrypoint sh mitmproxy-quic:latest \
  -c 'python3 /out/gen_quic_initials.py /out/quic_initials.json'   # novi vektorji za QUIC
```

Ni pokrito: postavitvi `A0` in `B1`, risanje v `plot.py`, `steer.py` proti pravemu stikalu
in brskalnik.

## Ročno preverjanje

`tcpdump` je samo v vsebniku `switch`; `eth1` je povezava do odjemalca, `eth2` do strežnika
in `eth3` do posrednika.

```sh
./orodja/start.sh B0                       # [--no-content-block] [--web] [--lazy]

docker exec clab-B0-switch tcpdump -i eth1 -nn -c 20 'tcp port 443 or udp port 443'

docker exec clab-B0-client curl -v --http2 \
  --cacert /opt/traffic/pki/trust.pem \
  --resolve <domena>:443:10.0.2.10 \
  -o /dev/null https://<domena>/index.html

docker exec clab-B0-mitm /opt/p4venv/bin/python \
  /opt/traffic/proxy/steer.py --stats /opt/traffic/out/switch_stats.json
```

Prestrežene seje so v `okolje/out/proxy_flows.jsonl`, dnevnik posrednika v
`okolje/out/mitm.log`. Seja, ki jo je zavrglo stikalo, se v `proxy_flows.jsonl` ne pojavi.
Števci stikala so `sni_seen`, `sni_blocked`, `sni_white`, `quic`, `ip_blocked`, `ip_white`,
`denied`, `quic_sni`, `quic_blocked` in `quic_white`.

Pot h3 preveriš v `B1`, ker `--http3-only` potrebuje strežnik z oglašenim `h3`; kontrolno
zahtevo ob zagonu nastaviš s `PROBE_URL`.

## Brskalnik

Odjemalec v `B1` teče na `browser:latest`. Namizje je v vsebniku, noVNC pa na naslovu, ki ga
izpiše `start.sh`, na primer `http://172.20.20.4:6080/vnc.html`.

```sh
./orodja/start.sh B1
./orodja/browse.sh B1 chromium https://www.cloudflare.com/
./orodja/browse.sh B1 firefox

FORCE_QUIC=1 ./orodja/browse.sh B1 chromium https://quic.anzepintar.com/
FORCE_QUIC=all ./orodja/browse.sh B1 chromium https://www.cloudflare.com/
```

Isto stran brez prestrezanja pogledaš v `C1`.

| spremenljivka | kaj je |
| :--- | :--- |
| `VNC_PASSWORD`, `VNC_GEOMETRY`, `VNC_WEB_PORT` | `diploma`, `1600x900x24`, `6080` |
| `WEB_PASSWORD` | žeton za `mitmweb`, kadar `start.sh` teče z `--web` |
| `FORCE_QUIC`, `NO_QUIC` | vsili oziroma izklopi h3; chromium sprejme tudi `FORCE_QUIC=all` |
| `USER_DATA_DIR`, `PROFILE_DIR`, `MARIONETTE_PORT` | profil chromiuma, profil in vrata firefoxa |

Zastavice so v `okolje/browser/chromium.sh` in `firefox.sh`, pravilnika v
`okolje/browser/policies/`; oboje se bere ob vsakem zagonu, zato slike ni treba graditi znova.
Vsiljeni HTTP/3 velja za točno ime gostitelja, ne za apex domeno.

## Čiščenje

```sh
sudo clab destroy -t B0.clab.yml --cleanup   # porusi eno postavitev

./orodja/rebuild.sh --clean                  # porusi vse, pobrisi meritve, nabor in slike
./orodja/rebuild.sh --clean-all              # se mitmproxy-quic, browser in bmv2
./orodja/reclaim.sh                          # lastnistvo datotek nazaj sebi
```

Skript ne poganjaj pod `sudo`. Programi meritev in `start.sh` sami kličejo `sudo clab` tam,
kjer je res potreben; sicer datoteke nastanejo v lasti roota in naslednji zagon ne more več
pisati čeznje. Če se to zgodi, pomaga `sudo chown -R "$USER:$USER" okolje`.
