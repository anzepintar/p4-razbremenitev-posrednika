# Testno okolje

Primerjava dveh rešitev za filtriranje šifriranega prometa ob eni sami neodvisni
spremenljivki — prisotnosti stikala. Vsi ukazi tečejo iz imenika `testno_okolje`.

| postavitev | pot | namen |
| :--- | :--- | :--- |
| `A0` | odjemalec — posrednik — strežnik | meritev: ves promet prek posrednika |
| `B0` | odjemalec — stikalo — posrednik — strežnik | meritev: stikalo razbremeni posrednika po naslovu in domeni |
| `A1` | odjemalec — posrednik — prehod → splet | ročno testiranje v brskalniku na resničnih straneh |
| `B1` | odjemalec — stikalo — posrednik — prehod → splet | ročno testiranje v brskalniku na resničnih straneh |

Posrednik teče v transparentnem načinu (`--mode transparent@8080`): QUIC (UDP/443) prestreže
prek TPROXY, TCP/443 pa prek `REDIRECT` in `SO_ORIGINAL_DST`. Prestrezanje QUIC-a doda fork
mitmproxy iz `mitmproxy-quic-transparent`. Vnose v tabeli `ip_policy` in `sni_policy` ob
zagonu zapiše `common/proxy/steer.py` prek P4Runtime (gRPC 10.20.1.2:9559); ločenega
krmilnika ni. Vrata bmv2 so fiksna: 1 = odjemalec, 2 = strežnik oziroma prehod, 3 = posrednik.

## Gradnja

Potrebuješ `docker`, `containerlab` in fork mitmproxy — privzeto se išče v
`../mitmproxy-quic-transparent`, drugo pot podaš z `MITM_SRC`.

```sh
./common/rebuild.sh          # nabor, seznami, slike; vse od začetka
```

Posamezni koraki, če jih rabiš ločeno:

```sh
./common/build_testset.py    # nabor strani iz LNU-Phish (~129 MB, 1000 domen)
./common/gen_lists.py        # seznami in razdelitev domen iz experiment.yml
./common/build.sh            # slike docker
```

Slika `mitmproxy-quic:latest` se zgradi le, če je še ni; kontekst njene gradnje je izvorna
koda forka, ne imenik `common`. Po spremembi forka:

```sh
docker rmi mitmproxy-quic:latest && ./common/build.sh
```

Enako velja za `browser:latest` (odjemalec v `A1` in `B1`): gradi se le, če je še ni, ker so
brskalnika z namizjem okoli 1,4 GB in ju meritev ne potrebuje. Ker stoji na `client:latest`, jo osveži
tudi po spremembi `client/Dockerfile`:

```sh
docker rmi browser:latest && ./common/build.sh
```

## Nastavitev

Vse nastavlja **`common/experiment.yml`** — to je edina datoteka, ki jo urejaš. Iz nje se
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
    unknown: 50       # ni na nobenem seznamu; iz te skupine teče promet ozadja
traffic:
  cases:
    brez_quic: 0.0    # delež zahtev prek HTTP/3
    z_quic: 1.0
matrix:
  modes: [brez, ip_black, ip_white, sni_black, sni_white, content_block]
  background_mbps: 100
  policy_rps: 100
  duration_s: 30
  repeats: 3
```

Vsak način iz `matrix.modes` potrebuje svojo skupino domen; če je skupina 0, to pove že
`experiment.py` ob branju in ne šele sredi serije. Razdelitev je determinstična (sha1 imena
domene) in med zagoni enaka; vsota skupin ne sme preseči `total`. Po vsaki spremembi poženi
`./common/gen_lists.py` — datotek v `common/lists/` ne urejaj ročno, ker jih prepiše.

Kje se skupina uveljavi:

| skupina | mehanizem | v A0 | v B0 |
| :--- | :--- | :--- | :--- |
| `ip_black` (ip črni seznam) | naslov `10.0.2.11` | posrednik (`--block-list`) | stikalo, ob prvem paketu |
| `ip_white` (ip beli seznam) | naslov `10.0.2.12` | posrednik tunelira (`--ignore-hosts`) | stikalo, mimo posrednika |
| `sni_black` (domenski črni seznam) | `domain_black.txt` | posrednik (`--block-list`) | stikalo, ob `ClientHello` |
| `sni_white` (domenski beli seznam) | `domain_white.txt` | posrednik tunelira | posrednik tunelira |
| `content_block` (vsebinski črni seznam) | `content_rules.txt` | posrednik, po dešifriranju | posrednik, po dešifriranju |
| `unknown` | — | dešifrira se | dešifrira se |

Beli seznam ima prednost pred črnim sam od sebe: ignorirana seja postane surov tok, filter
`~d` pa velja le za HTTP. Blokira se po glavi `Host`, ne po SNI, zato se ujame tudi
prikrivanje domene. `content_rules.txt` je pravilnik za `content_block.py`, ki teče le z
zastavico `--content-block` in lovi tisto, česar stikalo ne more videti.

Kaj odjemalec potegne, določa `load.object_kb`: pri `0` dokument strani (`index.html`), sicer
`/big.bin` te velikosti. Pri `object_kb > 0` način `content_block` izgubi pomen, ker `big.bin`
oznake nima.

## Meritev

Merljivi sta `A0` in `B0`, ker odjemalec potrebuje lokalni nabor. Vse bere `measure.sh` iz
`experiment.yml`; v ukazni vrstici ne podajaš ničesar.

```sh
./common/measure.sh            # matrika (privzeto)
./common/measure.sh calibrate  # rampa sočasnosti za določitev background_mbps
./common/plot.py               # grafi in tabela iz že izmerjenega
```

Vsaka celica matrike je en tek z **dvema sočasnima tokovoma odjemalca pri istem
`quic_share`**: `ozadje` (skupina `unknown`, stalna bitna hitrost `background_mbps`, meri se)
in `politika` (skupina načina, stalna frekvenca `policy_rps`, aktivira pot filtriranja). Pri
načinu `brez` toka `politika` ni; ta celica je izhodišče, iz katerega se izračuna mejna cena
ostalih načinov. Zavora na bajtih je za blokirani promet slepa, ker ta ne prenese bajtov, zato
ima runner ločeno zavoro na zahtevah.

Matrika je `A0`/`B0` × `brez_quic`/`z_quic` × šest načinov = 24 celic krat `repeats`. Vrstni
red zank je ponovitev → postavitev → protokol → način, zato se postavitev postavi in poruši
le dvakrat na ponovitev. Pri privzetih nastavitvah traja serija okoli ure.

Rezultat gre v `out/matrix/r<ponovitev>/<postavitev>/<protokol>/<način>/`, kalibracija pa v
`out/calibrate/<postavitev>/<protokol>/w<sočasnost>/`.

## Metrike

Vseh pet je definiranih v vsaki celici, zato je vsak graf ena metrika čez vso matriko.

| | metrika | ključ | definicija |
| :-- | :--- | :--- | :--- |
| M1 | propustnost dovoljenega prometa | `goodput_mbps` | bajti toka `ozadje` skozi `duration_s` |
| M2 | latenca dovoljenega prometa | `total_p50_ms`, `total_p95_ms` | p50 in p95 `time_total` |
| M3 | razbremenitev posrednika | `offload_pct` | delež zahtev, ki pri posredniku ne odprejo seje |
| M4 | cena uveljavitve | `cpu_ms_per_request_<vozlišče>` | CPU vozlišča na zahtevo |
| M5 | čas do razsodbe | `verdict_p50_s` | p50 `time_total` dokumentov toka `politika` |

**Pravilnost politike ni šesta metrika, ampak varovalo.** `policy_ok_pct` je delež strani toka
`politika` s pričakovanim izidom, računan po straneh. Celica pod 99 % dobi šrafiran stolpec in
je izločena iz vseh trditev o razmerjih — brez tega bi »B0 je hitrejši« lahko pomenilo le »B0
ni blokiral«.

Troje je vredno vedeti o definicijah:

- **Hitrosti se delijo s konfiguriranim trajanjem**, nikoli z razponom časovnih žigov vrstic;
  razpon je pri teku z redkimi vrsticami blizu nič in hitrost odleti v nesmisel.
- **Razbremenitev se šteje po sejah, ne po paketih.** Posrednik ima v `A0` svoj vmesnik za vsak
  krak seje, v `B0` pa oba kraka po istem, zato razmerje paketov pri enakem vedenju da 0 % za
  `A0` in −87 % za `B0`. Seje šteje `proxy_stats.py` ob začetku seje in ne ob odgovoru, ker
  ubita (`flow.kill()`) in tunelirana seja odgovora nimata — prav ti dve pa dokazujeta
  razbremenitev. Seja se pripiše toku po skupini domene, ker gresta oba tokova z istega naslova.
- **Mejno ceno** dobiš kot razliko celice in izhodiščne celice (`brez`) pri isti postavitvi in
  istem protokolu.

Števci stikala so kumulativni za vse življenje postavitve, zato se berejo pred in po teku
(`switch_before.json`, `switch_after.json`) in odštejejo, tako kot števci vmesnikov.

## Grafi in rezultati

Sedem datotek v `out/graf/`, številke v `out/results.json`, tabela vseh celic v
`out/results.md`. Vsak graf ima dve plošči za protokola, na osi x načine, v vsaki skupini
stolpca `A0` in `B0`; prečke napake so razpon min–max čez ponovitve.

| datoteka | kaj kaže |
| :--- | :--- |
| `m1_propustnost.png` | propustnost dovoljenega prometa |
| `m2_latenca.png` | latenca p50 in p95 |
| `m3_razbremenitev.png` | delež zahtev, ki posrednika ne doseže |
| `m4_cpu.png` | CPU na zahtevo pri posredniku in stikalu |
| `m5_razsodba.png` | čas do razsodbe |
| `pregled.png` | toplotna karta prednosti `B0` pred `A0` čez vso matriko |
| `kalibracija.png` | rampa iz `measure.sh calibrate` |

V `pregled.png` se metrike primerjajo z večkratnikom, obrnjenim tako, da je nad 1 vedno bolje
ne glede na smer metrike. Izjema je razbremenitev, ki je že odstotek in se primerja z razliko
v odstotnih točkah. Prazna celica pomeni, da politika tam ni bila veljavna.

## Testi

Trije nivoji po tem, kaj potrebujejo za zagon. Nivo določa imenik, oznako pa `conftest.py`
doda samodejno.

| nivo | kaj preverja | kaj potrebuje | koliko |
| :--- | :--- | :--- | :--- |
| `unit` | seznami, kodiranje ključa, ukaz `curl`, pravilnik vsebine, razdelitev domen, razčlenitev meritve, izračun celice | samo Python | 112 |
| `integration` | meje razčlenjevalnika SNI iz `steering.p4` na sestavljenih `ClientHello` | bere `steering.p4` | 16 |
| `e2e` | poti zahteve skozi tekočo postavitev, števci stikala, `connection_strategy` | postavitev `B0` | 22 |

```sh
python3 -m pytest                 # vse; e2e se preskoči brez postavitve
python3 -m pytest -m "not e2e"    # brez vsebnikov
python3 -m pytest -m e2e          # šele po ./common/start.sh B0
```

`test_sni.py` preverja, da ima regexp za posrednikov `--block-list` isto semantiko kot ternarni
ključ za stikalo — brez tega bi bila domena lahko blokirana v eni postavitvi, v drugi pa ne.
`test_clienthello.py` bere konstante neposredno iz `steering.p4`, zato test in program ne
moreta raziti. `test_matrika.py` in `test_summarize.py` zamejujeta napake, ki so se v meritvi
res zgodile: 502 ni blokada ampak okvara, delež se računa po straneh in ne po zahtevah,
hitrost se deli s trajanjem in ne z razponom, števci stikala se odštejejo, manjkajoče vozlišče
ni nič, seje ozadja ne štejejo med seje politike.

Ordering, ki se ne sme razdreti: `TestCrnaDomena` mora biti zadnji v `test_poti.py`, ker
odjemalec zavrnjen `ClientHello` ponavlja še približno minuto in vsaka ponovitev poveča
`sni_seen`. `TestVrstniRed` potrebuje še nezahtevano domeno, ker posrednik povezave navzgor
združuje. Bela in privzeta pot se ločita po **izdajatelju potrdila**, ne po kodi odgovora:
izdajatelj posrednika pomeni dešifrirano, izdajatelj strežnika pa surov tunel.

Ni pokrito: postavitve `A0`, `A1` in `B1` (`conftest.py` je vezan na `B0`), risanje v
`plot.py`, `steer.py` proti pravemu stikalu in brskalnik.

## Ročno preverjanje

Pot posamezne zahteve pogledaš na tekoči postavitvi. `tcpdump` je samo v vsebniku `switch`;
`eth1` je povezava do odjemalca, `eth3` do posrednika in pokaže obe nogi hkrati.

```sh
./common/start.sh B0

docker exec clab-B0-switch tcpdump -i eth1 -nn -c 20 'tcp port 443 or udp port 443'
docker exec clab-B0-switch tcpdump -i eth3 -nn -c 20 'tcp port 443 or udp port 443'

docker exec clab-B0-client curl -v --http2 \
  --cacert /opt/traffic/pki/trust.pem \
  --resolve <domena>:443:10.0.2.10 \
  -o /dev/null https://<domena>/index.html

docker exec clab-B0-mitm /opt/p4venv/bin/python \
  /opt/traffic/proxy/steer.py --stats /opt/traffic/out/switch_stats.json
```

Prestrežene seje so v `common/out/proxy_flows.jsonl`, dnevnik posrednika v
`common/out/mitm.log`, razsodbe stikala pa v števcih, ki jih izpiše `steer.py --stats`. Seja,
ki jo je zavrglo stikalo, se v `proxy_flows.jsonl` ne pojavi — tako najhitreje ločiš zavrnitev
stikala od zavrnitve posrednika.

Pot h3 preveriš v `B1`, ker `--http3-only` potrebuje strežnik z oglašenim `h3`. Kontrolno
zahtevo ob zagonu nastaviš s `PROBE_URL`.

```sh
./common/start.sh B1
docker exec clab-B1-client curl -v --http3-only \
  --cacert /opt/traffic/pki/trust.pem https://quic.anzepintar.com/
sudo clab destroy -t B1.clab.yml --cleanup
```

## Brskalnik

Odjemalec v `A1` in `B1` teče na `browser:latest` s chromiumom in firefoxom. Namizje je **v
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
Zastavice so torej v imeniku `common` in jih spremeniš brez ponovne gradnje slike. Isti dve
skripti požene tudi `browse.sh`, ki namizje po potrebi zažene sam.

```sh
./common/start.sh A1
./common/browse.sh A1 chromium https://www.cloudflare.com/
./common/browse.sh A1 firefox
```

Brskalnik h3 sam po sebi uporabi šele, ko se glave `alt-svc` nauči in je ne označi za
pokvarjeno, zato je prva stran skoraj vedno HTTP/2. **`FORCE_QUIC=1`** domeno iz naslova
prisili v h3 pri obeh brskalnikih; namesto `1` lahko podaš svojo domeno, pri chromiumu pa tudi
`all` za vse. V dnevniku posrednika se potem vidi `GET https://... HTTP/3`.

```sh
FORCE_QUIC=1 ./common/browse.sh A1 chromium https://quic.anzepintar.com/
FORCE_QUIC=1 ./common/browse.sh A1 firefox https://quic.anzepintar.com/
FORCE_QUIC=all ./common/browse.sh A1 chromium https://www.cloudflare.com/
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
./common/start.sh B0 --content-block          # postavi
sudo clab destroy -t B0.clab.yml --cleanup    # poruši

SUDO= ./common/measure.sh                     # brez sudo

rm -rf common/out/*                           # počisti meritve
rm -f common/pki/trust.pem
```
