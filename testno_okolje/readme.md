# Testno okolje

Primerjava dveh rešitev za filtriranje šifriranega prometa ob eni sami neodvisni
spremenljivki — prisotnosti stikala. Vsi ukazi tečejo iz imenika `testno_okolje`.

Drevo loči dvoje: **`okolje/`** je tisto, kar vsak vsebnik vidi kot `/opt/traffic`
(nastavitve, koda odjemalca, dodatki posrednika, program stikala, seznami, potrdila,
rezultati), **`orodja/`** pa gostiteljske skripte, ki jih poganjaš sam. V vsebniku ni
ničesar iz `orodja/`, na gostitelju pa nič ne piše v `okolje/` mimo `gen_lists.py`
in meritve.

| postavitev | pot | namen |
| :--- | :--- | :--- |
| `C0` | odjemalec — strežnik | referenca: kaj zmore merilna oprema sama |
| `A0` | odjemalec — posrednik — strežnik | meritev: ves promet prek posrednika |
| `B0` | odjemalec — stikalo — posrednik — strežnik | meritev: stikalo razbremeni posrednika po naslovu in domeni |
| `B1` | odjemalec — stikalo — posrednik — prehod → splet | ročno testiranje v brskalniku na resničnih straneh |

Posrednik teče v transparentnem načinu (`--mode transparent@8080`): QUIC (UDP/443) prestreže
prek TPROXY, TCP/443 pa prek `REDIRECT` in `SO_ORIGINAL_DST`. Prestrezanje QUIC-a doda fork
mitmproxy iz `mitmproxy-quic-transparent`. Vnose v tabeli `ip_policy` in `sni_policy` ob
zagonu zapiše `okolje/proxy/steer.py` prek P4Runtime (gRPC 10.20.1.2:9559); ločenega
krmilnika ni. Vrata bmv2 so fiksna: 1 = odjemalec, 2 = strežnik oziroma prehod, 3 = posrednik.

Stikalo bere ime gostitelja iz obeh prenosov: iz `ClientHello` v TCP ga razčleni razčlenjevalnik
v `steering.p4`, iz začetnega paketa QUIC pa zunanja funkcija bmv2 `quic_sni.so`, ker je ta
paket šifriran. Obe poti pišeta v isto polje `meta.sni` in vprašata isto tabelo `sni_policy`,
zato je seznam en sam. Podrobnosti so v razdelku [SNI v QUIC](#sni-v-quic).

## Gradnja

Potrebuješ `docker`, `containerlab` in fork mitmproxy — privzeto se išče v
`../mitmproxy-quic-transparent`, drugo pot podaš z `MITM_SRC`.

```sh
./orodja/rebuild.sh          # nabor, seznami, slike; vse od začetka
```

Posamezni koraki, če jih rabiš ločeno:

```sh
./orodja/build_testset.py    # nabor strani iz LNU-Phish (~129 MB, 1000 domen)
./orodja/gen_lists.py        # seznami in razdelitev domen iz experiment.yml
./orodja/build.sh            # slike docker
```

Slika `mitmproxy-quic:latest` se zgradi le, če je še ni; kontekst njene gradnje je izvorna
koda forka, ne imenik `okolje`. Po spremembi forka:

```sh
docker rmi mitmproxy-quic:latest && ./orodja/build.sh
```

Tako se gradi tudi `bmv2-perf:1.15.5-modules`, na kateri stoji `p4-switch:latest`. Gradnja
bmv2 iz izvorne kode traja nekaj minut in je potrebna enkrat; slika mora biti prav ta, ker je
povezana z `-rdynamic` in zato zna naložiti `quic_sni.so` (glej [SNI v QUIC](#sni-v-quic)).
Po spremembi `quic_sni.cpp`, `quic_extern.cpp` ali `steering.p4` zadošča:

```sh
./orodja/build.sh            # p4-switch se prevede na novo, bmv2 se ne
```

Enako velja za `browser:latest` (odjemalec v `B1`): gradi se le, če je še ni, ker so
brskalnika z namizjem okoli 1,4 GB in ju meritev ne potrebuje. Ker stoji na `client:latest`, jo osveži
tudi po spremembi `client/Dockerfile`:

```sh
docker rmi browser:latest && ./orodja/build.sh
```

## Nastavitev

Vse nastavlja **`okolje/experiment.yml`** — to je edina datoteka, ki jo urejaš. Iz nje se
izpeljejo seznami, razdelitev domen, naslovi strežnika in celotna matrika meritve.

```yaml
domains:
  total: 100          # koliko domen iz nabora gre v meritev
  groups:
    ip_black: 10      # strežnik na blokiranem naslovu
    ip_white: 10      # strežnik na naslovu mimo posrednika
    sni_black: 10     # domena na črnem seznamu
    sni_white: 10     # domena na belem seznamu
    content_block: 10 # vsebina z oznako, ki jo ujame content_block.py
    unknown: 50       # ni na nobenem seznamu
protocols:
  h2: 0.0             # delež zahtev prek HTTP/3
  h3: 1.0
modes: [brez, ip_black, ip_white, sni_black, sni_white, content_block]
load:
  connect_timeout_s: 3.000
  max_time_s: 10
  object_kb: 0
```

Tu je samo tisto, kar je res skupno gostitelju in vsebniku. Trajanje, ogrevanje in obremenitev
so v programu meritve in v `meta.json` vsake celice, torej poleg namena in ne dve datoteki
stran.

`connect_timeout_s` je 3 s in ne 1 s: pri eni sekundi trči ob prvi PTO QUIC-a (RFC 9002,
`kInitialRtt` 333 ms), zato bi bil vsak tok, ki izgubi prvi `Initial`, zajamčeno štet kot
napaka — izmerjeno se je to pokazalo kot gruča iztekov pri 1001–1005 ms. `max_time_s` je 10 s,
ker je hkrati vgrajena meja latence pri iskanju (glej spodaj).

Vsak način iz `matrix.modes` potrebuje svojo skupino domen; enako velja za vsako skupino z
utežjo nad nič v `traffic.mix`. Če je skupina 0, to pove že `experiment.py` ob branju in ne
šele sredi serije; izjema je `unknown`, ki lahko nastane iz ostanka `total`. Razdelitev je
determinstična (sha1 imena domene) in med zagoni enaka; vsota skupin ne sme preseči `total`.
Po vsaki spremembi poženi `./orodja/gen_lists.py` — datotek v `okolje/lists/` ne urejaj
ročno, ker jih prepiše.

Kje se skupina uveljavi:

| skupina | mehanizem | v A0 | v B0 |
| :--- | :--- | :--- | :--- |
| `ip_black` (ip črni seznam) | naslov `10.0.2.11` | posrednik (`--block-list`) | stikalo, ob prvem paketu |
| `ip_white` (ip beli seznam) | naslov `10.0.2.12` | posrednik tunelira (`--ignore-hosts`) | stikalo, mimo posrednika |
| `sni_black` (domenski črni seznam) | `domain_black.txt` | posrednik (`--block-list`) | stikalo: TCP ob `ClientHello`, QUIC ob začetnem paketu |
| `sni_white` (domenski beli seznam) | `domain_white.txt` | posrednik tunelira | TCP: posrednik tunelira; QUIC: stikalo, mimo posrednika |
| `content_block` (vsebinski črni seznam) | `content_rules.txt` | posrednik, po dešifriranju | posrednik, po dešifriranju |
| `unknown` | — | dešifrira se | dešifrira se |

Belega seznama v TCP stikalo ne more uveljaviti samo: ko pride `ClientHello`, je trosmerno
rokovanje s posrednikom že končano in poti ni več mogoče zamenjati, zato tak tok tunelira
posrednik. V QUIC-u je ime v prvem paketu toka, zato stikalo belo domeno pošlje naravnost na
strežnik in posrednik je sploh ne vidi.

Beli seznam ima prednost pred črnim sam od sebe: ignorirana seja postane surov tok, filter
`~d` pa velja le za HTTP. Blokira se po glavi `Host`, ne po SNI, zato se ujame tudi
prikrivanje domene. `content_rules.txt` je pravilnik za `content_block.py`, ki lovi tisto,
česar stikalo ne more videti.

`content_block.py` je **privzeto vklopljen**, ker ga meritev vedno potrebuje; brez njega bi
način `content_block` tiho dal `policy_ok_pct` 0 %. Izklopi ga `--no-content-block`, kar se
splača v `B1`: pravilo je `~bs`, torej filter po podnizu telesa, in tak filter prisili
posrednika, da vsak odgovor v celoti shrani v pomnilnik namesto da bi ga pretakal. V meritvi
je ta cena enaka v obeh postavitvah in zajeta že v izhodišču `brez`, na resničnem spletu pa
le upočasni brskanje, ker oznake `x-block-me-7f3a` nobena resnična stran nima.

Kaj odjemalec potegne, določa `load.object_kb`: pri `0` dokument strani (`index.html`), sicer
`/big.bin` te velikosti. Pri `object_kb > 0` način `content_block` izgubi pomen, ker `big.bin`
oznake nima.

## SNI v QUIC

`ClientHello` je v QUIC-u v začetnem paketu (`Initial`), ta pa je šifriran z `AES-128-GCM`.
Ključ ni skrivnost — po RFC 9001 se izpelje iz ciljnega ID povezave (`HKDF-Extract` s stalno
soljo, nato `HKDF-Expand-Label`) — a v P4 ni ne HKDF ne AES. Zato to opravi zunanja funkcija
bmv2 iz `okolje/switch/quic_sni.cpp` (OpenSSL), ki jo `steering.p4` kliče kot `quicSni`.

Funkcija dobi neprebrani del paketa (bmv2 `Packet::data()`, torej breme UDP) in naredi štiri
stvari:

1. odstrani zaščito glave in dešifrira odjemalčev `Initial`,
2. iz okvirjev `CRYPTO` sestavi zapis rokovanja TLS, tudi če je razdeljen čez več datagramov
   ali pride v napačnem vrstnem redu,
3. iz sestavljenega dela prebere `server_name` in ga zapiše v `meta.sni` v isti obliki kot
   razčlenjevalnik TLS (64 bajtov, ime poravnano desno),
4. ime in izbrano pot si zapomni po četvorčku, zato naslednji paketi toka ne terjajo ne
   dešifriranja ne poizvedbe v `sni_policy`.

Tretji korak ne čaka na cel `ClientHello`, ampak na razširitev `server_name`. To ni
podrobnost: **curl pošlje `ClientHello` v dveh datagramih** (s hibridnim ključem je zapis
okoli 1600 bajtov), enako firefox. Ime je v prvem, ker ga knjižnice TLS postavijo med prve
razširitve, zato razsodba pade ob prvem paketu toka in bela domena res gre mimo posrednika.
Če bi čakali na cel zapis, bi bil prvi datagram že pri posredniku in poti ne bi bilo več
mogoče zamenjati.

Pot se izbere enkrat na tok in se ne spreminja (`quicSni.pin`):

| razsodba ob začetnem paketu | pot | števec |
| :--- | :--- | :--- |
| ime je na belem seznamu | naravnost na strežnik, mimo posrednika | `quic_white` |
| ime je na črnem seznamu | zavrže se | `quic_blocked` |
| imena ni na nobenem seznamu | posrednik | `quic` |
| imena (še) ni | posrednik | `quic` |

Zadnja vrstica je tok, pri katerem imena tudi po prvem paketu ni (razsekan zapis, kjer je
`server_name` šele v drugem datagramu, ali sploh ne QUIC): tak paket gre na posrednika in tok
ostane pripet nanj, ker posrednik zdaj sejo že vidi. Črna razsodba je izjema: velja tudi za
tok, ki je na posrednika že pripet. Števec `quic_sni` šteje tokove, pri katerih je bilo ime
prebrano, torej po en paket na tok.

Meje so konstante v `steering.p4` in gredo v zunanjo funkcijo kot argumenti konstruktorja:

| konstanta | privzeto | pomen |
| :--- | :--- | :--- |
| `MAX_SNI_NAME` | 63 | najdaljše ime; ista meja kot pri razčlenjevalniku TLS |
| `QUIC_TIMEOUT_MS` | 60000 | koliko časa tok brez paketa ostane v predpomnilniku |
| `QUIC_MAX_FLOWS` | 65536 | največ hkratnih tokov; ob polnem se pobriše starejša polovica |
| `QUIC_MAX_CRYPTO` | 16384 | največji zapis rokovanja, ki se še sestavlja |

Modul se naloži ob zagonu (`--load-modules` v `start_switch.sh`), zato mora biti
`simple_switch_grpc` povezan z `-rdynamic`; v prevodu CMake za bmv2 to ni privzeto, zato je
dodano v `bmv2.Dockerfile`. Slika ima zato novo oznako `bmv2-perf:1.15.5-modules` — stara
`bmv2-perf:1.15.5` modula ne naloži, bmv2 v `out/switch.log` zapiše `Skipping module` in
`start.sh` se ustavi s pojasnilom. Program se ne prevaja več prek gonilnika `p4c`, ampak
neposredno s `p4c-bm2-ss --emit-externs`, ker gonilnik te zastavice ne sprejme.

Česa stikalo v QUIC-u ne vidi: migracija povezave da nov četvorček in s tem nov tok, 0-RTT z
imenom iz prejšnje seje nima `ClientHello`, ECH pa `server_name` skrije enako kot pri TCP.
Zaporedje razsodbe in pripenjanja je varno, ker ima `simple_switch` eno samo vhodno nit in
zunanja funkcija dela pod ključavnico; na cilju z več vzporednimi cevovodi bi bilo treba
razsodbo in pripenjanje združiti v en klic.

## Meritve

Meritev je razbita na **šest samostojnih programov**. Vsak ustreza enemu razdelku poročila,
ima svoj namen, svoj izhod v `out/<ime>/` in traja okoli desetih minut. Poganjaš jih ločeno in
ponoviš samo tistega, ki ga potrebuješ; vsak ob zagonu izpiše, kaj meri in zakaj.

Ponovitev je ena. Prečk napake zato ni — namesto njih povedo o uporabnosti točke varovala
(pravilnost, delež napak, izraba odjemalca).

```sh
./orodja/m1_posrednik.sh     # fork mitmproxy: HTTP/2 proti HTTP/3
./orodja/m2_pravilnost.sh    # ali je politika uveljavljena pravilno
./orodja/m3_stikalo.sh       # kaj stane stikalo v poti
./orodja/m4_referenca.sh     # zgornja meja brez vsega
./orodja/m5_vrste.sh         # vpliv po vrstah prometa
./orodja/m6_prag.sh          # pri katerem deležu se stikalo splača
./orodja/plot.py             # grafi in tabele iz vsega izmerjenega
```

Vsi programi delijo strojnico v `orodja/lib.sh`: postavljanje topologije, kontrolna zahteva
pred celico, ogrevanje, zajem števcev in `nodestats`, ter zapis `meta.json` z nastavitvami, s
katerimi je celica res tekla. Vsaka celica je **en sam tok odjemalca**, ki je v celoti ene
vrste prometa — tako je izmerjena cena te vrste čista.

### Poglavje »Razvoj in testiranje rešitve«

**`m1_posrednik`** — kako se fork obnese pri HTTP/3 v primerjavi s HTTP/2. Postavitev `A0`,
promet samo iz skupine `unknown`, torej brez politike, da se meri čisto prestrezanje. *Namen:*
ugotoviti ceno, ki jo prinese prestrezanje QUIC-a v primerjavi z TLS/TCP.

### Iskanje največje vzdržne hitrosti

`m1`, `m3` in `m4` ne delajo rampe po sočasnosti, ampak **iščejo največjo hitrost brez
izgube** po metodi iz RFC 2544 (§26.1). Rampa bi odgovarjala na »kakšna je krivulja«, vprašanje
pa je »katera je največja vzdržna hitrost«; poleg tega rampa krmili sočasnost, pri kateri se
zahteve kopičijo v vrsto, zato izguba sploh ni dobro definirana.

Poskus pri hitrosti *R* uspe, če velja oboje:

| pogoj | vir |
| :--- | :--- |
| `errors_pct` = 0 | `metrics.jsonl` |
| `rate_achieved_rps ≥ 0,98 · R` | `summary.json` |

Meja latence je vgrajena prek `load.max_time_s`: zahteva, ki traja dlje, postane napaka, zato
»brez izgube« pomeni tudi p95 pod 10 s. Merilo uveljavi `orodja/verdict.py`, ki zapiše
`verdict.json` v imenik poskusa in vrne izhodno kodo za lupino.

Potek je v `search_max` v `orodja/lib.sh`:

1. **uokvirjanje** — od 8 zahtev/s podvajaj, dokler poskus ne pade;
2. **bisekcija** — med zadnjo uspelo in prvo padlo, dokler ni razmik pod 5 %; ločljivost je
   relativna, ker je HTTP/2 pri ~200 in HTTP/3 pri ~25 zahtevah/s;
3. **potrditev** — pri najdeni hitrosti še daljši tek v `potrjeno/`, iz katerega se poročajo
   propustnost, rokovanje in CPU.

To je 7–10 poskusov namesto petih grobih stopenj, poskusi pa se zgostijo prav okoli kolena,
zato je tudi slika boljša. Rezultat je v `max.json`, vsi maksimumi skupaj pa v
`out/m4_referenca/maksimumi.md`.

Med poskusi se ogrevalni prehod in branje števcev stikala preskočita (`CELL_WARMUP_PASS=0`,
`CELL_SWITCH=0`), sicer bi režija presegla sam poskus; `search_max` ogreje enkrat na začetku,
števce pa prebere pri potrditvi.

**`m2_pravilnost`** — ali je uveljavljanje pravilno pri posredniku in pri stikalu, v obeh
protokolih. Nizka frekvenca, da nasičenje ne skrije napak. Sodba se sestavi iz **treh
neodvisnih virov**: izida pri odjemalcu (`policy_ok_pct`), števcev stikala (ali je bila
izbrana pričakovana pot) in dnevnika sej posrednika (ali je sejo sploh videl). *Namen:*
dokazati, da so IP beli in črni seznam ter domenski beli in črni seznam res implementirani
pravilno, preden se karkoli meri.

**Sto odstotkov ni pričakovana vrednost pri domenskem seznamu v TLS prek TCP.**
Razčlenjevalnik v `steering.p4` je po naravi P4 omejen: prehodi le **šest razširitev**
(`extension0` … `extension5`), preskočiti zna le telesa do `MAX_EXT_BODY` (256 B), ime pa sme
biti dolgo največ `MAX_SNI_NAME` (63 B). Poleg tega vidi en sam paket, zato razdeljenega
`ClientHello` ne more sestaviti. Odjemalec, ki postavi `server_name` za veliko razširitev —
na primer `key_share` s hibridnim ključem — ali ga potisne v sedmo režo, gre mimo. Meje so
pripete v `tests/integration/test_clienthello.py` (`test_sni_cez_zadnjo_rezo`,
`test_velika_razsiritev_pred_sni_ustavi_razclenjevanje`), tako da test in program ne moreta
raziti. Delež je zato odvisen od tega, kaj pošiljajo odjemalci, in je po literaturi za tak
razčlenjevalnik nekje med 95 in 99 odstotki.

V QUIC-u te meje ni: zunanja funkcija sestavi okvirje `CRYPTO` čez datagrame do
`QUIC_MAX_CRYPTO` (16 kB), zato ime najde tudi tam, kjer ga razčlenjevalnik TCP ne bi. Pot
QUIC je pri izluščanju imena torej **robustnejša** od poti TCP, kar je v nasprotju s prvim
občutkom in je vredno omembe v poročilu.

Zaradi tega je prag pričakovane pravilnosti v `plot.py` odvisen od mehanizma: 95 % za domenski
seznam v HTTP/2 in 99 % povsod drugod. Šrafiran stolpec pomeni »pod pričakovanim«, ne
»neveljavno« — vrednost je vseeno izmerjena in se poroča.

**`m3_stikalo`** — isti promet in isto iskanje kot `m1`, le postavitev `B0`. Razlika proti
`m1` je natanko cena stikala v poti: koliko pade zgornja meja, koliko se podaljša rokovanje in
koliko procesorja porabi stikalo samo. *Namen:* ločiti ceno stikala od cene posrednika.

### Poglavje »Ovrednotenje rešitve«

**`m4_referenca`** — postavitev `C0` je samo odjemalec in strežnik na neposredni povezavi.
*Namen:* zgornja meja merilne opreme. Brez nje ni mogoče reči, ali je omejitev v rešitvi ali v
odjemalcu; vse, kar dosežeta `A0` in `B0`, mora biti pod njo. Graf `m4_referenca` postavi
`C0`, `A0` in `B0` enega ob drugega.

**`m5_vrste`** — `A0` in `B0` pri stalni obremenitvi, ki jo vzameta kot 70 % manjšega od
maksimumov iz `m1` in `m3`, da obe postavitvi merita pri isti obremenitvi in obe varno pod
nasičenjem, za vsako od šestih vrst
prometa posebej. Meri se propustnost, rokovanje in predvsem **breme posrednika: CPU deljen s
številom poslanih zahtev, tudi tistih, ki posrednika sploh niso dosegle**. Prav ta delitelj je
bistven — pove, koliko dela je posredniku prihranjeno na enoto ponujenega prometa, in ne le,
kako hitro obdela to, kar vidi. *Namen:* pokazati, kje `B0` pridobi, kje izgubi in koliko
bremena se dejansko premakne.

**`m6_prag`** — pri katerem deležu obhodnega prometa se stikalo splača. Iz čistih cen v `m5`
se izračuna presečišče, ta meritev pa ga potrdi z mešanicami 25, 50 in 75 odstotkov.
*Namen:* odgovoriti na vprašanje vpeljave — koliko prometa mora biti obhodnega, da se dodaten
skok povrne.

## Metrike

| ključ | pomen |
| :--- | :--- |
| `goodput_mbps` | propustnost dovoljenega prometa; blokirani promet ne šteje |
| `handshake_p50_ms`, `handshake_p95_ms` | `time_appconnect`, torej trajanje rokovanja |
| `total_p50_ms`, `total_p95_ms` | latenca celotne zahteve |
| `requests` | **poslanih** zahtev v merilnem oknu |
| `cpu_ms_per_request_<vozlišče>` | CPU vozlišča deljen s poslanimi zahtevami |
| `proxy_kb_per_request` | koliko prometa posrednik sploh prejme na zahtevo |
| `policy_ok_pct` | delež zahtev s pričakovanim izidom |
| `proxy_sessions` | koliko sej je posrednik odprl |
| `switch` | razlika števcev stikala čez celico |
| `errors_pct`, `cpu_util_<vozlišče>` | varovali veljavnosti |

Kar je vredno vedeti o definicijah:

- **Hitrosti se delijo s konfiguriranim trajanjem**, nikoli z razponom časovnih žigov;
  trajanje je `duration_s` minus `warmup_s`, oboje zapisano v `meta.json` celice.
- **CPU se bere iz cgroup** (`cpu.stat`, `usage_usec`) pred in po teku, tako kot števci
  vmesnikov. Kvoto vzame `nodestats.py` iz `cpu.max`; pri vozlišču brez omejitve je delitelj
  število jeder gostitelja, zato je `cpu_util_*` vezan na to, kar postavitev res dobi.
- **Prag rentabilnosti** je presečišče dveh premic. Pri deležu obhoda *p* je breme posrednika
  na zahtevo `(1-p)·pregled + p·obhod`, presečišče pa

  ```
  p* = (a_pregled - b_pregled) / ((a_pregled - a_obhod) - (b_pregled - b_obhod))
  ```

  Števec je pribitek, ki ga `B0` plača za dodaten skok, imenovalec razlika prihrankov. `p*` nad
  1 pomeni, da se pri tem mehanizmu stikalo ne splača nikoli — tako se na primer obnese
  domenski beli seznam v HTTP/2, kjer stikalo v TCP obhoda ne more izvesti.

## Veljavnost

Trditev velja le za točko, ki prestane vsa varovala; `veljavnost.md` jih zbere na celico.

| pogoj | prag | zakaj |
| :--- | :--- | :--- |
| `policy_ok_pct` | ≥ prag mehanizma (95 % za domenski seznam v HTTP/2, sicer 99 %) | sicer razlika ni v hitrosti, ampak v tem, kaj je bilo blokirano; taka celica dobi šrafiran stolpec |
| `errors_pct` | ≤ 1 % | točka nad tem meri iztek, ne zmogljivosti |
| `cpu_util_client` | pod 0,8 | odjemalec zažene proces `curl` na zahtevo; če se nasiti prvi, se postavitvi ustavita pri isti vrednosti in primerjava ne pove nič. Taka točka dobi na grafu odprt znak |
| `cpu_util_switch`, `cpu_util_mitm` | poročata se | pove, katera komponenta je bila ozko grlo |

Pred vsako celico gre kontrolna zahteva. Če ne vrne 200, se postavitev enkrat postavi na novo;
če tudi potem ne odgovori, se blok prekine. Brez tega je odmrla podatkovna ravnina tiho
zapisana kot rezultat.

## Grafi in rezultati

Vsak program zapiše v `out/<ime>/`: slike v `graf/` kot `.png`, tabelo celic v `results.md`,
varovala v `veljavnost.md` in strojno berljiv `results.json`. Slike so široke 6,3 palca,
pisava 9 pt, barve privzete matplotlib; stolpčni grafi imajo ploščo na protokol, HTTP/2 nad
HTTP/3.

| slika | iz | kaj kaže |
| :--- | :--- | :--- |
| `m1_iskanje`, `m1_rokovanje`, `m1_cpu` | m1 | dosežena proti ponujeni hitrosti z najdenim maksimumom, rokovanje in CPU posrednika |
| `m2_pravilnost` + `pravilnost.md` | m2 | delež pravilnih razsodb po vrstah prometa in števci stikala |
| `m3_iskanje`, `m3_rokovanje`, `m3_cpu` | m3 | isto kot m1, a s stikalom; CPU je od stikala |
| `m4_referenca`, `m4_rokovanje` + `maksimumi.md` | m4 | `C0`, `A0` in `B0` eden ob drugem in tabela vseh maksimumov |
| `m5_propustnost`, `m5_rokovanje`, `m5_breme` | m5 | po vrstah prometa; `m5_breme` je CPU posrednika na poslano zahtevo |
| `m6_prag` + `prag.md` | m6 | breme proti deležu obhoda, presečišče in izmerjene točke |

## Testi

Trije nivoji po tem, kaj potrebujejo za zagon. Nivo določa imenik, oznako pa `conftest.py`
doda samodejno.

| nivo | kaj preverja | kaj potrebuje | koliko |
| :--- | :--- | :--- | :--- |
| `unit` | seznami, kodiranje ključa, ukaz `curl`, pravilnik vsebine, razdelitev domen, uteži mešanice, razčlenitev meritve, izračun celice | samo Python | 144 |
| `integration` | meje razčlenjevalnika SNI iz `steering.p4` na sestavljenih `ClientHello`, branje SNI iz pravih paketov `Initial`, ujemanje imen števcev | bere `steering.p4`, za QUIC še slika `p4-switch` | 26 |
| `e2e` | poti zahteve skozi tekočo postavitev (TCP in QUIC), števci stikala, `connection_strategy` | postavitev `B0` | 31 |

```sh
python3 -m pytest                 # vse; e2e se preskoči brez postavitve
python3 -m pytest -m "not e2e"    # brez vsebnikov
python3 -m pytest -m e2e          # šele po ./orodja/start.sh B0
```

`test_quic.py` požene isto kodo, ki teče v stikalu: slika `p4-switch` ima poleg modula še
`quic_selftest`, ki bere šestnajstiške datagrame in izpiše prebrano ime, test pa mu podtakne
vektorje iz `tests/data/quic_initials.json` (pravi `Initial` iz aioquica in sestavljeni robni
primeri — razdeljen `ClientHello`, obrnjen vrstni red, predolgo ime, smeti) in en pravi
razdeljen `ClientHello`, posnet s curlom v `B0` (`posnet_` se pri ponovnem generiranju
ohrani). Če slike ni, se preskoči. Vektorje na novo narediš z:

```sh
docker run --rm -v "$PWD/tests/data:/out" --entrypoint sh mitmproxy-quic:latest \
  -c 'python3 /out/gen_quic_initials.py /out/quic_initials.json'
```

Isti test veže tudi imena števcev: `STAT_*` v `steering.p4`, `STATS` v `steer.py` in
`SWITCH_KEYS` v `plot.py` morajo biti isti seznam v istem vrstnem redu, sicer bi se meritvi
tiho zamenjala dva stolpca.

`test_sni.py` preverja, da ima regexp za posrednikov `--block-list` isto semantiko kot ternarni
ključ za stikalo — brez tega bi bila domena lahko blokirana v eni postavitvi, v drugi pa ne.
`test_clienthello.py` bere konstante neposredno iz `steering.p4`, zato test in program ne
moreta raziti. `test_matrika.py` in `test_summarize.py` zamejujeta napake, ki so se v meritvi
res zgodile: 502 ni blokada ampak okvara, hitrost se deli s trajanjem in ne z razponom,
blokirani promet ne šteje v propustnost in latenco, ogrevanje izpade iz okna, CPU je razlika
in ne absolutna vrednost cgroup ter se deli s poslanimi zahtevami, števci stikala se
odštejejo, manjkajoče vozlišče ni nič, prag rentabilnosti nad 1 pomeni, da se stikalo ne
splača nikoli.

Zajem paketov v `conftest.py` teče s `tcpdump -l`: brez tega se izhod zbira v medpomnilniku
in datoteka ostane prazna, dokler se ne nabere vseh `-c` paketov, zato je test, ki jih
pričakuje manj, videl prazen zajem in je bil odvisen od prometa prejšnjih testov.

Ordering, ki se ne sme razdreti: `TestCrnaDomena` in `TestQuicCrnaDomena` morata biti zadnja v
`test_poti.py`, ker odjemalec zavrnjeni `ClientHello` oziroma `Initial` ponavlja še približno
minuto in vsaka ponovitev poveča `sni_seen` oziroma `quic_blocked`. `TestVrstniRed` potrebuje še nezahtevano domeno, ker posrednik povezave navzgor
združuje. Bela in privzeta pot se ločita po **izdajatelju potrdila**, ne po kodi odgovora:
izdajatelj posrednika pomeni dešifrirano, izdajatelj strežnika pa surov tunel.

Ni pokrito: postavitvi `A0` in `B1` (`conftest.py` je vezan na `B0`), risanje v
`plot.py`, `steer.py` proti pravemu stikalu in brskalnik.

## Ročno preverjanje

Pot posamezne zahteve pogledaš na tekoči postavitvi. `tcpdump` je samo v vsebniku `switch`;
`eth1` je povezava do odjemalca, `eth3` do posrednika in pokaže obe nogi hkrati.

```sh
./orodja/start.sh B0

docker exec clab-B0-switch tcpdump -i eth1 -nn -c 20 'tcp port 443 or udp port 443'
docker exec clab-B0-switch tcpdump -i eth3 -nn -c 20 'tcp port 443 or udp port 443'

docker exec clab-B0-client curl -v --http2 \
  --cacert /opt/traffic/pki/trust.pem \
  --resolve <domena>:443:10.0.2.10 \
  -o /dev/null https://<domena>/index.html

docker exec clab-B0-mitm /opt/p4venv/bin/python \
  /opt/traffic/proxy/steer.py --stats /opt/traffic/out/switch_stats.json
```

Prestrežene seje so v `okolje/out/proxy_flows.jsonl`, dnevnik posrednika v
`okolje/out/mitm.log`, razsodbe stikala pa v števcih, ki jih izpiše `steer.py --stats`. Seja,
ki jo je zavrglo stikalo, se v `proxy_flows.jsonl` ne pojavi — tako najhitreje ločiš zavrnitev
stikala od zavrnitve posrednika.

Pot QUIC-a se vidi na istih števcih: `quic_sni` pove, pri koliko tokovih je stikalo prebralo
ime, `quic_white` pove, koliko paketov je šlo mimo posrednika, `quic_blocked` koliko jih je
zavrglo in `quic` koliko jih je poslalo na pregled. Za belo domeno mora `eth2` videti
datagrame z naslova odjemalca, `eth3` pa nobenega:

```sh
docker exec clab-B0-switch tcpdump -i eth2 -nn -c 5 'udp port 443 and src host 10.0.1.10'
docker exec clab-B0-client curl -v --http3-only \
  --cacert /opt/traffic/pki/trust.pem \
  --resolve <bela-domena>:443:10.0.2.10 \
  -o /dev/null https://<bela-domena>/index.html
```

Pot h3 preveriš v `B1`, ker `--http3-only` potrebuje strežnik z oglašenim `h3`. Kontrolno
zahtevo ob zagonu nastaviš s `PROBE_URL`.

```sh
./orodja/start.sh B1
docker exec clab-B1-client curl -v --http3-only \
  --cacert /opt/traffic/pki/trust.pem https://quic.anzepintar.com/
sudo clab destroy -t B1.clab.yml --cleanup
```

## Brskalnik

Odjemalec v `B1` teče na `browser:latest` s chromiumom in firefoxom. Namizje je **v
vsebniku**: `browser/vnc.sh` zažene `Xvfb` na `:99`, `openbox`, `x11vnc` in `websockify` z
noVNC, ti pa ga postrežejo na vratih 6080. Odpri naslov, ki ga izpiše `start.sh`, na primer
`http://172.20.20.4:6080/vnc.html`, in vpiši geslo (privzeto `diploma`). Na gostitelju ne rabiš
ničesar — ne strežnika X ne `xauth` — in enako dela prek SSH.

| nastavitev | privzeto | kaj je |
| :--- | :--- | :--- |
| `VNC_PASSWORD` | `diploma` | geslo za noVNC |
| `VNC_GEOMETRY` | `1600x900x24` | velikost namizja |
| `VNC_WEB_PORT` | `6080` | vrata noVNC |

Na namizju z desnim klikom dobiš meni z obema brskalnikoma; zaganja ju `diploma-chromium` in
`diploma-firefox`, kar sta simbolni povezavi na `browser/chromium.sh` in `browser/firefox.sh`.
Zastavice so torej v imeniku `okolje/browser` in jih spremeniš brez ponovne gradnje slike. Isti dve
skripti požene tudi `browse.sh`, ki namizje po potrebi zažene sam.

```sh
./orodja/start.sh B1
./orodja/browse.sh B1 chromium https://www.cloudflare.com/
./orodja/browse.sh B1 firefox
```

Brskalnik h3 sam po sebi uporabi šele, ko se glave `alt-svc` nauči in je ne označi za
pokvarjeno, zato je prva stran skoraj vedno HTTP/2. **`FORCE_QUIC=1`** domeno iz naslova
prisili v h3 pri obeh brskalnikih; namesto `1` lahko podaš svojo domeno, pri chromiumu pa tudi
`all` za vse. V dnevniku posrednika se potem vidi `GET https://... HTTP/3`.

```sh
FORCE_QUIC=1 ./orodja/browse.sh B1 chromium https://quic.anzepintar.com/
FORCE_QUIC=1 ./orodja/browse.sh B1 firefox https://quic.anzepintar.com/
FORCE_QUIC=all ./orodja/browse.sh B1 chromium https://www.cloudflare.com/
```

Chromium dobi `--origin-to-force-quic-on`, firefox pa v profil `user.js` z
`network.http.http3.alt-svc-mapping-for-testing` in
`network.http.http3.force-use-alt-svc-mapping-for-testing`. Za `all` pri firefoxu ni ustreznice,
ker njegova preizkusna preslikava velja za eno domeno.

Da h3 prek posrednika sploh steče, sta bila potrebna dva popravka. Firefox **sam izklopi h3,
ko v zbirki najde tuji koren** — natanko to je CA posrednika — in domeno trajno prestavi na
TCP (`hasThirdPartyRoots=1`, nato `ExcludeHttp3` v dnevniku `nsHttp`); zato pravilnik postavi
`network.http.http3.disable_when_third_party_roots_found` na `false`. Poleg tega firefox
`ClientHello` razdeli na dva datagrama in vsakega dopolni z ničlami **za** paketom; fork je to
polnilo bral kot pokvarjen paket in sejo zavrgel, zato je bil popravljen
`_client_hello_parser.py` (glej spodaj).

CA posrednika je nov ob vsakem `clab deploy`, zato ga `start.sh` in vsak `browse.sh` znova
zapišeta v odjemalca (`browser/trust_nss.sh`): v sistemsko zbirko za `curl` in v NSS zbirko za
chromium. Firefox ga dobi iz pravilnika `Certificates.Install`, ki kaže na
`/opt/traffic/pki/trust.pem` in se bere ob vsakem zagonu.

**DoH in ECH sta zaklenjena izklopljena** (`browser/policies/`). DNS mora ostati v čistopisu,
ker ga stikalo prepušča po `PORT_DNS`, ECH pa bi skril `server_name` in `sni_policy` bi ostal
slep — filtriranje bi se v `B1` vedlo drugače kot v meritvi. Stanje preveriš v
`about:policies` in `chrome://policy`.

**Odjemalcu je izklopljen IPv6** (`disable_ipv6` v `exec`). Vsebnik ima na upravljavskem
vmesniku `eth0` globalni naslov IPv6 in privzeto pot IPv6, ki gre mimo celotne postavitve;
brskalnik pa IPv6 raje uporabi. Zaradi tega je h3 na domeno z zapisom AAAA odletel po `eth0`,
se po štirih sekundah iztekel in tiho padel na TCP prek posrednika — QUIC se torej ni
prestrezal, čeprav je vse skupaj delovalo. Z izklopljenim IPv6 gre `Initial` po `eth1`,
chromium sprejme potrdilo posrednika in pošlje prave zahteve HTTP/3.

Popravek v forku: `quic_parse_client_hello_from_datagrams` je doslej vsak `packet_dropped`
iz aioquica razumel kot neveljaven `ClientHello`. Polnilo za zadnjim paketom datagrama pa ni
paket in ga mora prejemnik prezreti (RFC 9000, 12.2), zato se zdaj napaka sproži le, kadar
datagram ni dal nobenega paketa. Brez tega firefoxovega h3 ni bilo mogoče prestreči, curl in
chromium pa sta delovala, ker polnilo spravita v paket.

**Gostitelji z ECH so posebna zgodba.** `cloudflare-quic.com` v DNS oglašuje nastavitev ECH,
zato chromium pravo domeno skrije in navzven pošlje javno ime `cloudflare-ech.com`; posrednik
izda potrdilo za tisto ime (`DNS:cloudflare-ech.com`), chromium ga zavrne (`certificate
unknown`), pri vsiljenem QUIC pa ni več poti na TCP — od tod `ERR_QUIC_PROTOCOL_ERROR`. `curl`
ECH ne pozna, zato tam ista stran po h3 dela. Rešuje ga zastavica
`--disable-features=EncryptedClientHello` v `browser/chromium.sh`, torej vsak zagon prek
`browse.sh` ali menija na namizju; sama politika `EncryptedClientHelloEnabled` ne zadošča.
Firefoxu ECH izklopi pravilnik (`network.dns.echconfig.enabled`). To ni le nadloga pri testu:
prav ECH je tisto, kar bi stikalu v `B1` skrilo `server_name`.

Chromiumu so izklopljena ozadna omrežna opravila (`--disable-background-networking` in
podobno), ker `update.googleapis.com` in `android.clients.google.com` drugače preplavita
`proxy_flows.jsonl`. Googlove lastne domene so v chromiumu pripete (pinning), zato jih
posrednik ne more prestreči; v dnevniku se to vidi kot `certificate unknown` in ni napaka
postavitve.

Stikalo v `B1` prepušča le TCP, QUIC, DNS in ICMP, zato brskalnikov mDNS tiho pade v števec
`denied`; to je pričakovano in strani ne prizadene. Chromium teče z `--no-sandbox`, ker gre za
vsebnik za enkratno uporabo.

Privzeto teče `mitmdump`, ki spletnega vmesnika nima; z `--web` steče `mitmweb` in `start.sh`
izpiše naslov oblike `http://172.20.20.3:8081/?token=diploma` (brez `?token=` vrne 403, geslo
zamenjaš z `WEB_PASSWORD`). Za merjeni postavitvi pusti `mitmdump`, ker vmesnik doda režijo.

## Ročni zagon in čiščenje

```sh
./orodja/start.sh B0                          # postavi (vsebinski filter je privzet)
sudo clab destroy -t B0.clab.yml --cleanup    # poruši

SUDO= ./orodja/m1_posrednik.sh                # brez sudo

rm -rf okolje/out/*                           # počisti meritve
rm -f okolje/pki/trust.pem
```

Vsebniki tečejo kot root in pišejo v priklopljeni `okolje/`, zato po vsakem zagonu del
datotek pripade rootu in `gen_lists.py` ali `plot.py` ne moreta več pisati čez. Lastništvo
prevzame nazaj `./orodja/reclaim.sh`; `rebuild.sh` in vsak program meritve ga pokličeta
sama na začetku, program meritve pa še enkrat tik pred `plot.py`, ker med tekom nastanejo nove
datoteke v lasti roota.

**Skript ne poganjaj pod `sudo`.** Programi meritev in `start.sh` sami kličejo `sudo clab` tam,
kjer je res potreben. Če celotno skripto pognaš z `sudo`, je `SUDO_USER` sicer še vedno tvoje
ime in `reclaim.sh` ravna prav, vse ostalo pa nastane v lasti roota in naslednji zagon brez
`sudo` ne more več pisati. Če se to zgodi:

```sh
sudo chown -R "$USER:$USER" okolje
```
