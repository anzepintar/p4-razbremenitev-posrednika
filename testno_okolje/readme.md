# Testno okolje

## Primeri

Primerjamo štiri različne primere:

### client_server

Samo odjemalec in strežnik, brez stikala in posrednika.

client -- server

Namen: potrditev, da odjemalec in strežnik delujeta, ločeno od vsega ostalega.

### mitm_baseline

Ves promet med odjemalcem in strežnikom gre preko mitmproxy-ja.

client -- mitm proxy -- server

Namen: osnovni primer s katerim se naša rešitev primerja, mora biti vsaj boljša od tega.

Posrednik promet le prestreže in posreduje naprej. Z addonom `content_block.py` pregleda tudi
vsebino strani in phishing blokira, glej [Pregled vsebine](#pregled-vsebine).

### mitm_controller

Ves promet gre prek mitmproxy-ja. Del prometa ne pregleda ampak ga le posreduje naprej. Za to odločitev skrbi controller.

client -- mitm proxy -- server
              |
              |
          controller

Namen: primer s katerim se naša rešitev dejansko primerja.

### p4_baseline

Ves promet med odjemalcem in strežnikom potuje prek stikala p4, ki pa ta promet zgolj posreduje.

client -- p4 -- server

Namen: za ugotavljanje osnovnih vrednosti pri meritvah

### p4_controller_mitm

Ves promet pride do stikala p4, ki pa je glede na pravila (controller) posredovan direktno na cilj oziroma prek mitm proxy-ja.

        controller
           |
client -- p4 -- server
           + mitmproxy

Namen: ugotovitev vpliva mitmproxy-ja na celotno rešitev

### p4_controller_ids

Ves promet pride do stikala p4, ki pa je glede na pravila (controller) posredovan direktno na cilj, oziroma je promet posredovan direktno in je kopija prometa posredovana na suricato.

        controller
           |
client -- p4 -- server
           + suricata

Namen: ugotovitev vpliva ids na celotno rešitev

### p4_full

Ves promet pride do stikala p4, ki pa je glede na pravila (controller) posredovan direktno na cilj, prek mitm proxy-ja, oziroma je promet posredovan direktno in je kopija prometa posredovana na suricato. V primeru zaznave nedovoljenega prometa se zmanjša stopnja zaupanja odjemalca in posledično gre naslednjič promet prek mitm proxy-ja.

        controller
           |
client -- p4 -- server
           + mitm_proxy
           + suricata


Namen: naša rešitev




## Tabela primerov

Ime                          |  p4  | controller | mitmproxy | ids
:--------------------------- | :--: | :--------: | :------:  | :--:
client_server.clab.yml       |      |            |           |     
mitm_controller.clab.yml     |      |     1      |    1      |     
mitm_baseline.clab.yml       |      |            |    1      |     
p4_baseline.clab.yml         |  1   |            |           |     
p4_controller_ids.clab.yml   |  1   |     1      |           |  1  
p4_controller_mitm.clab.yml  |  1   |     1      |    1      |     
p4_full.clab.yml             |  1   |     1      |    1      |  1  


## Namestitev

Vsi ukazi v tem readme tečejo iz `testno_okolje/`, vmesnega `cd` ni. Skripte se same
postavijo v svoj imenik, zato jih kličemo po poti (`common/...`).

```sh
common/build_testset.py    # osnovni 50+50, testni 950+50 (glej testni_podatki/vir.txt)
common/build.sh
```

### ročno:

```sh
docker build -t server:latest        -f common/server/Dockerfile     common/server
docker build -t client:latest        -f common/client/Dockerfile     common/client
docker build -t proxy:latest         -f common/proxy/Dockerfile      common/proxy
docker build -t bmv2-perf:1.15.5     -f common/switch/bmv2.Dockerfile common/switch
docker build -t p4-switch:latest     -f common/switch/Dockerfile     common/switch
docker build -t p4-controller:latest -f common/controller/Dockerfile common/controller
docker build -t ids:latest           -f common/ids/Dockerfile        common/ids
```

`p4-switch` se gradi v dveh stopnjah: prva s `p4lang/p4c` prevede `common/switch/steering.p4`,
druga na `bmv2-perf` doda le prevedeni program. Napaka v `.p4` se tako pokaže
že pri gradnji, ne šele sredi meritve. `p4c` in bmv2 na gostitelju nista potrebna.

### Gradnja bmv2

Dve sliki


## Testi delovanja sistema ...

```sh
PYTHONPATH=common/client python3 -m pytest common/tests -q   # enotski
common/tests/integration.sh                                  # H2/H3 do Caddyja
common/tests/integration_mitm.sh                             # H2/H3 skozi mitmproxy
common/tests/integration_p4.sh                               # vse štiri postavitve p4_*
common/tests/integration_controller.sh                       # mitm_controller
```

Zadnja dva za razliko od prvih dveh potrebujeta containerlab, ker postavita pravo topologijo.
Sama jo tudi podreta. Če je containerlabu nastavljen SUID, ju poženi s
`SUDO= common/tests/integration_p4.sh`.
## Zagon

```sh
sudo clab deploy -t client_server.clab.yml --reconfigure

clab exec -t client_server.clab.yml --label clab-node-name=server --cmd "caddy start --config /opt/traffic/server/Caddyfile"

common/trust.sh client_server                # pki/trust.pem iz Caddyjevega CA
common/capture.sh client_server client       # neobvezno, zajem prometa

clab exec -t client_server.clab.yml --label clab-node-name=client --cmd "env SSLKEYLOGFILE=/opt/traffic/out/keys.log python3 -m runner --config /opt/traffic/scenario.yml --duration 30"
```

`--config` | pot do `scenario.yml` (privzeto `/opt/traffic/scenario.yml`)
`--duration` | trajanje v sekundah, prepiše `run.duration`
`--requests` | število nalaganj strani na odjemalca; če je podan, `--duration` ne velja
`--insecure` | brez preverjanja certifikatov in brez čakanja na CA
`--speed` | skrči čakanje med zahtevami (`think_time` in `rate`); zaporedje zahtev ostane isto


Ustavitev:

```sh
common/capture.sh --stop client_server client

clab exec -t client_server.clab.yml --label clab-node-name=server --cmd "caddy stop"
sudo clab destroy -t client_server.clab.yml --cleanup
```

### Postavitev s posrednikom

Ista pot, vmes se zažene še mitmproxy. Vrstni red je pomemben, ker `trust.sh` pobere samo
tiste CA, ki že obstajajo:

```sh
sudo clab deploy -t mitm_baseline.clab.yml --reconfigure

clab exec -t mitm_baseline.clab.yml --label clab-node-name=server --cmd "caddy start --config /opt/traffic/server/Caddyfile"

common/trust.sh mitm_baseline           # samo Caddy

docker exec -d clab-mitm_baseline-mitm sh -c 'exec mitmdump "$@" >>/opt/traffic/out/mitm.log 2>&1' _ \
    --set confdir=/data/mitmproxy \
    --set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
    --set keep_host_header=true \
    -s /opt/proxy/sni_passthrough.py \
    --mode reverse:https://10.0.2.10:443@8443 \
    --mode reverse:https://10.0.2.11:443@8444 \
    --mode reverse:https://10.0.2.12:443@8445

common/trust.sh mitm_baseline           # zdaj Caddy + mitmproxy

clab exec -t mitm_baseline.clab.yml --label clab-node-name=client --cmd "env SSLKEYLOGFILE=/opt/traffic/out/keys.log python3 -m runner --config /opt/traffic/scenario.yml --duration 30"
```

Isti `mitmdump` ukaz velja za vse postavitve s posrednikom, spremeni se le ime vozlišča
(`clab-<topologija>-mitm`). Vrata 8443/8444/8445 ustrezajo pravilom `iptables` v topologiji,
ki preusmerijo promet za 10.0.2.10/11/12.

Če naj posrednik vsebino tudi pregleduje in blokira, se ukazu doda še en addon:

```sh
    -s /opt/proxy/sni_passthrough.py \
    -s /opt/proxy/content_block.py \
```

Dnevnik posrednika:

```sh
tail -f common/out/mitm.log
```

### Postavitev s stikalom P4

Stikalo je bmv2 (`simple_switch_grpc`) s programom `common/switch/steering.p4`. Vozlišče se zbudi
prazno, zato ga po `deploy` zaženemo sami — teče v ospredju, torej z `docker exec -d`:

```sh
sudo clab deploy -t p4_baseline.clab.yml --reconfigure

docker exec -d clab-p4_baseline-switch sh -c \
    'exec /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1'
docker exec clab-p4_baseline-switch ss -lnt | grep 9559     # bmv2 tece

clab exec -t p4_baseline.clab.yml --label clab-node-name=server --cmd "caddy start --config /opt/traffic/server/Caddyfile"
common/trust.sh p4_baseline

clab exec -t p4_baseline.clab.yml --label clab-node-name=client --cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests 40"
```

`SWITCH_ARGS` pred `start_switch.sh` doda poljubne argumente za bmv2, npr.
`SWITCH_ARGS="--log-console -L debug"`. Izpis na posamezen paket dela **samo v sliki
`p4-switch:debug`** (`BMV2_PROFILE=debug common/build.sh`) — v privzeti gradnji so logging makri
odstranjeni že ob prevajanju, zato `--log-console` tam pokaže le zagonske vrstice. Skripta sama
dvigne vmesnike, izklopi offloade (sicer bi bmv2 pošiljal pokvarjene kontrolne vsote) in prevedeni
program skopira v `common/switch/build/`, od koder ga bo bral krmilnik.

Vrata stikala so v vseh P4 topologijah enaka:

Vrata | Vmesnik | Vozlišče        | Mreža
:---: | :------ | :-------------- | :----
1     | eth1    | client          | 10.0.1.0/24
2     | eth2    | server          | 10.0.2.0/24
3     | eth3    | mitm            | 10.0.3.0/24
4     | eth4    | ids (zrcaljenje)| —
5     | eth5    | controller      | 10.20.1.0/30, samo P4Runtime gRPC

Postavitve, ki katerega od vozlišč nimajo, tista vrata preprosto preskočijo; oštevilčenje ostane
enako, da sta program in krmilnik za vse postavitve ista.

Usmerjanje med mrežami je vzidano v `steering.p4` (`const entries`), ker je naslavljanje fiksno —
zato `p4_baseline` krmilnika ne potrebuje. Krmilnik upravlja samo tabelo `steering`, ki odloča,
ali gre promet posameznega odjemalca naravnost, prek mitmproxy-ja ali s kopijo na IDS.

Stanje podatkovne ravnine se da pogledati z bmv2 CLI:

```sh
docker exec -i clab-p4_baseline-switch simple_switch_CLI <<<"table_dump steering"
docker exec -i clab-p4_baseline-switch simple_switch_CLI <<<"counter_read stats 1"   # brez poti
```

`stats` šteje zavržene pakete: `0` ne-IPv4 (pričakovano, npr. IPv6 ND), `1` brez poti, `2` potekel TTL.

**bmv2 je programsko stikalo.** Absolutne latence P4 postavitev niso primerljive s `client_server`
— pri istem naboru 53 zahtev smo izmerili p50 4,7 ms brez stikala proti 19,8 ms prek bmv2 (p95
6,1 ms proti 52,2 ms). Smiselne so le razlike **znotraj** P4 veje, torej med `p4_baseline`,
`p4_controller_mitm`, `p4_controller_ids` in `p4_full`.

### Postavitev s krmilnikom

```yaml
policy:
  mitm: {high: direct, medium: direct, low: via_mitm}
  ids: {high: mirror, medium: mirror, low: mirror}
  full: {high: mirror, medium: mirror, low: via_mitm}
```

#### p4_controller_mitm

Stikalo se tu zažene brez vzidanega programa (`NO_PIPELINE=1`), cevovod potisne krmilnik:

```sh
sudo clab deploy -t p4_controller_mitm.clab.yml --reconfigure

docker exec -d clab-p4_controller_mitm-switch sh -c \
    'exec env NO_PIPELINE=1 /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1'
docker exec -d clab-p4_controller_mitm-controller sh -c \
    'exec python3 /opt/traffic/controller/controller.py --grpc-addr 10.20.1.2:9559 --policy mitm \
     >>/opt/traffic/out/controller.log 2>&1'

docker exec -i clab-p4_controller_mitm-switch simple_switch_CLI <<<"table_dump SwitchIngress.steering"
```

Nato kot pri ostalih postavitvah: `caddy start` → `trust.sh` → `mitmdump` (isti ukaz kot zgoraj)
→ `trust.sh` → `runner`.

#### mitm_controller

Brez stikala. Posredniku se doda addon `controller_bypass.py`, ki za vsako sejo vpraša krmilnik
(`CONTROLLER_URL`, privzeto `http://10.20.3.1:8080`) in ob odgovoru `direct` sejo spusti mimo
nepregledano:

```sh
docker exec -d clab-mitm_controller-controller sh -c \
    'exec python3 /opt/traffic/controller/controller.py --policy mitm \
     >>/opt/traffic/out/controller.log 2>&1'

#   ... mitmdump kot zgoraj, z dodatnim addonom:
    -s /opt/proxy/controller_bypass.py \
```

Ker se poizveduje ob vsaki povezavi, je čas poizvedbe del izmerjene latence. Vsaka odločitev je
zapisana v `common/out/bypass.jsonl` skupaj z `decide_ms`, tako da se jo da pri analizi odšteti
(v naših zagonih ~2 ms).

**Obid pri HTTP/3 ni mogoč.** mitmproxy zna sejo spustiti mimo le pri TCP; ob `ignore_connection`


### Postavitev z IDS

Pravila naredi `common/ids/gen_rules.py` iz istega manifesta kot Caddyfile, po eno na phishing domeno.

```sh
common/ids/gen_rules.py     # common/ids/testset.rules, 50 pravil za nabor 'osnovni'
```

```sh
sudo clab deploy -t p4_controller_ids.clab.yml --reconfigure

docker exec -d clab-p4_controller_ids-switch sh -c \
    'exec env NO_PIPELINE=1 /opt/switch/start_switch.sh >>/opt/traffic/out/switch.log 2>&1'
docker exec -d clab-p4_controller_ids-controller sh -c \
    'exec python3 /opt/traffic/controller/controller.py --grpc-addr 10.20.1.2:9559 --policy ids \
     >>/opt/traffic/out/controller.log 2>&1'
docker exec -d clab-p4_controller_ids-ids sh -c \
    'exec /opt/ids/start_ids.sh >>/opt/traffic/out/ids.log 2>&1'
docker exec -d clab-p4_controller_ids-ids sh -c \
    'exec python3 /opt/ids/alert_forward.py >>/opt/traffic/out/forward.log 2>&1'
```

### Postavitev p4_full

Celotno postavitev zažene ena skripta:

```sh
common/start.sh p4_full --content-block
clab exec -t p4_full.clab.yml --label clab-node-name=client \
    --cmd "python3 -m runner --config /opt/traffic/scenario.yml --requests 40"
```

`start.sh <topologija> [--policy ime] [--content-block]` zna vse postavitve in zažene le tiste dele,
ki jih topologija ima, v pravem vrstnem redu. Po zagonu Caddyja iz **strežniškega** kontejnerja
obišče vseh 100 domen, da Caddy izda certifikate: `tls internal` jih izda šele ob prvi zahtevi za
domeno, zato je prej med meritvijo vsake toliko kakšna stran odpovedala s `SSL connect error`
(v eni seriji 48 zahtev). Ogrevanje teče iz strežnika in ne z odjemalca zato, ker bi sicer promet
do phishing domen šel skozi IDS in posrednik ter znižal zaupanje še pred meritvijo.

### Stanje postavitve

```sh
clab inspect --all                                  # vsa vozlišča vseh topologij
clab inspect -t client_server.clab.yml
docker exec clab-client_server-client ip -br addr    # so se exec ukazi topologije izvedli?
```
## Primerjava

`common/compare.sh` požene zagone z istim `seed` in istim številom zahtev, torej z
identičnim zaporedjem zahtev:

Zagon | Topologija | Posebnost | Meri
:--- | :--- | :--- | :---
`A` | `client_server` | — | osnovna vrednost brez posrednika
`B` | `mitm_baseline` | `sni_passthrough.py` | cena prestrezanja TLS
`C` | `mitm_baseline` | `+ content_block.py` | prestrezanje in pregled vsebine
`D` | `p4_baseline` | — | osnovna vrednost P4 veje
`E` | `p4_controller_mitm` | politika `mitm` | cena preusmerjanja na posrednik
`F` | `p4_controller_ids` | politika `ids` | cena zrcaljenja na IDS
`G` | `p4_full` | politika `full`, `+ content_block.py` | rešitev z zanko zaupanja
`H` | `mitm_controller` | `+ controller_bypass.py`, `+ content_block.py` | izbirni pregled brez stikala

B in C sta ista topologija in ista pot, razlikujeta se le po naloženem addonu — zato je
`C − B` cena pregleda vsebine, `B − A` pa cena prestrezanja. Znotraj P4 veje je `D` izhodišče,
`E − D` cena preusmerjanja, `F − D` cena zrcaljenja. Absolutnih vrednosti med vejama (`A`–`C`
proti `D`–`G`) se ne primerja, ker je bmv2 programsko stikalo.

`H` je neposredni protiutež `G`: ista ideja izbirnega pregleda, a odločitev pade šele v posredniku
namesto v stikalu. `G − H` je torej cena oziroma prihranek tega, da odločanje prestavimo v podatkovno
ravnino.

```sh
common/compare.sh          # 40 nalaganj strani na odjemalca, vsi zagoni
common/compare.sh 100
common/compare.sh 40 ADG   # samo izbrani zagoni
```

Serija traja dolgo, zato se sama zavije v `systemd-inhibit`, da gostitelj med meritvijo ne gre v
mirovanje — sicer se v podatkih pojavi vrzel in trajanje zagona ni več uporabno.

Skripta za vsak zagon sama postavi in podre topologijo prek `start.sh`. `clab deploy` in `destroy`
potrebujeta `sudo`; kdor je containerlabu nastavil SUID (glej [Zahteve](#zahteve)), ga izklopi s
`SUDO= common/compare.sh`. Ker sedem zagonov traja dolgo, je izbira podmnožice priporočljiva.
Rezultate pusti v `common/out/<zagon>/` (poleg meritev še `verdicts.jsonl`, `alerts.jsonl`,
`controller.jsonl` in `eve.json`). Na koncu pokliče `compare.py`, ki naredi `common/out/compare.md`
in `common/out/compare.json` z razdelki: latence po protokolu in kategoriji z razlikami, matrika
zaznave (TP/FP/TN/FN), tabela SNI proti vsebini, **vir zaznave** (IDS po pravilih proti IDS po SNI
iz QUIC proti blokadi po vsebini), **odziv krmilnika** (znižanja zaupanja in `reaction_ms`),
hevristika po pragovih in cena pregleda.

Povzetek se da narediti tudi ločeno, brez ponovnega zagona:

```sh
common/compare.py
```
### Grafi

`common/compare.sh` na koncu pokliče še `common/plot.py`, ki iz `out/<zagon>/` naredi štiri slike
PNG v `common/out/graf/`. Enako se da pognati ločeno:

```sh
common/plot.py                 # vsi zagoni
common/plot.py --runs ADG      # samo izbrani
```

## Zajem prometa

```sh
common/capture.sh client_server client          # privzeto vmesnik eth1
common/capture.sh client_server server eth1
common/capture.sh --stop client_server client
```

Zajem nastane v `common/out/<topologija>-<vozel>.pcap`. Za dešifriranje mora runner teči
z `SSLKEYLOGFILE=/opt/traffic/out/keys.log` (kot v ukazih zgoraj), v Wiresharku pa
*Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* → `common/out/keys.log`.
Ista datoteka odklene HTTP/2 in HTTP/3.

## Konfiguracija

Vse nastavitve so v `common/scenario.yml`: odjemalci in njihovi izvorni naslovi, profili
(razmerje h2/h3, oznake, hitrost, delež domain frontinga) ter `run` (trajanje, seed,
izhodni imenik, CA, zgornja meja podvirov).

Menjava nabora (`testset.set`: `osnovni` ali `testni`):

```sh
# v common/scenario.yml spremeni testset.set
common/gen_caddyfile.py
clab exec -t client_server.clab.yml --label clab-node-name=server \
    --cmd "caddy reload --config /opt/traffic/server/Caddyfile"
```

`gen_caddyfile.py` se da pognati tudi nad drugačnim scenarijem:

```sh
common/gen_caddyfile.py --config common/tests/scenario.local.yml -o /tmp/sites.caddy
```

## Cleanup

```sh
rm -rf common/out/*  # meritve, pcap, keys.log, presoje, primerjava
rm -f common/pki/trust.pem
```

Vsebina `common/out/` nastane v kontejnerju kot root, a jo je vseeno mogoče pobrisati brez sudo,
ker je imenik last uporabnika. Če je iz starejšega zagona ostal še imenik `common/pki/caddy`
(nastal je, ko je Caddy hranil CA pod `/opt/traffic/pki`), ga odstrani prek kontejnerja,
ker ima pravice 0700 in root lastništvo:

```sh
docker run --rm -v "$PWD/common/pki:/w" server:latest rm -rf /w/caddy
```

Novejše postavitve tega imenika ne delajo več — Caddy hrani CA v `/data` znotraj
kontejnerja (privzetek slike `caddy:2`), `trust.sh` pa ga pobere z `docker exec`.