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


## Zahteve

Uporabnik mora biti v skupini `docker`, sicer vsak `docker` ukaz zahteva `sudo`:

```sh
sudo usermod -aG docker "$USER"    # enkratno, nato se odjavi in prijavi
docker info >/dev/null && echo ok  # preveri, da gre brez sudo
```

Root potrebujeta samo `clab deploy` in `clab destroy`, ker containerlab povezuje omrežne
imenske prostore vozlišč. Vsi ostali ukazi tečejo kot navaden uporabnik: `clab exec`,
`clab inspect`, `docker`, skripte v `common/` in testi.

Kdor tudi tega noče, lahko enkratno nastavi SUID na binarni datoteki, kar `deploy` in
`destroy` sprosti navadnemu uporabniku:

```sh
sudo chmod u+s "$(which containerlab)"
```

## Namestitev

```sh
cd common
./build_testset.py    # osnovni 50+50, testni 950+50 (glej testni_podatki/vir.txt)
./build.sh            # sites.caddy + slike client, server, proxy, tests
```

`build.sh` zgradi `client`, `server`, `proxy` in `tests`. Slik `p4-switch`,
`p4-controller` in `ids` še ni, ker so imeniki `common/switch/`, `common/controller/` in
`common/ids/` prazni. Zato sta trenutno zaženljivi samo topologiji `client_server` in
`mitm_baseline`; ostale se bodo pri `clab deploy` ustavile na manjkajoči sliki.

Posamezno sliko se da zgraditi tudi ločeno:

```sh
cd common
docker build -t server:latest -f server/Dockerfile server
docker build -t client:latest -f client/Dockerfile client
docker build -t proxy:latest  -f proxy/Dockerfile  proxy
docker build -t tests:latest  -f tests/Dockerfile  .
```

## Testi

```sh
cd common
PYTHONPATH=client python3 -m pytest tests -q             # enotski, brez dockerja
docker run --rm -v "$PWD:/opt/traffic:ro" tests:latest   # enotski, v sliki
./tests/integration.sh                                   # H2/H3 do Caddyja
./tests/integration_mitm.sh                              # H2/H3 skozi mitmproxy
```

Integracijski skripti ne potrebujeta containerlaba — Caddy in mitmproxy poženeta na
loopbacku gostitelja in za sabo pospravita. Po spremembi kode v `client/runner/` je treba
sliki `client` in `tests` zgraditi na novo, sicer se preverja stara koda.

## Zagon

Vsi ukazi tečejo iz `testno_okolje/`.

```sh
sudo clab deploy -t client_server.clab.yml --reconfigure

clab exec -t client_server.clab.yml --label clab-node-name=server \
    --cmd "caddy start --config /opt/traffic/server/Caddyfile"

cd common
./trust.sh client_server                # pki/trust.pem iz Caddyjevega CA
./capture.sh client_server client       # neobvezno, zajem prometa

clab exec -t ../client_server.clab.yml --label clab-node-name=client \
    --cmd "SSLKEYLOGFILE=/opt/traffic/out/keys.log python3 -m runner --config /opt/traffic/scenario.yml --duration 30"
```

Runner sprejme štiri argumente:

Argument | Pomen
:--- | :---
`--config` | pot do `scenario.yml` (privzeto `/opt/traffic/scenario.yml`)
`--duration` | trajanje v sekundah, prepiše `run.duration`
`--requests` | število nalaganj strani na odjemalca; če je podan, `--duration` ne velja
`--insecure` | brez preverjanja certifikatov in brez čakanja na CA

Rezultata sta `common/out/metrics.jsonl` (ena vrstica na zahtevo) in `common/out/summary.json`
(p50/p95/p99 po protokolu, kategoriji in odjemalcu). Runner povzetek izpiše tudi na zaslon.

Ustavitev:

```sh
cd common
./capture.sh --stop client_server client

cd ..
clab exec -t client_server.clab.yml --label clab-node-name=server --cmd "caddy stop"
sudo clab destroy -t client_server.clab.yml --cleanup
```

### Postavitev s posrednikom

Ista pot, vmes se zažene še mitmproxy. Vrstni red je pomemben, ker `trust.sh` pobere samo
tiste CA, ki že obstajajo:

```sh
sudo clab deploy -t mitm_baseline.clab.yml --reconfigure

clab exec -t mitm_baseline.clab.yml --label clab-node-name=server \
    --cmd "caddy start --config /opt/traffic/server/Caddyfile"

cd common
./trust.sh mitm_baseline                # samo Caddy

docker exec -d clab-mitm_baseline-mitm mitmdump \
    --set confdir=/data/mitmproxy \
    --set ssl_verify_upstream_trusted_ca=/opt/traffic/pki/trust.pem \
    --set keep_host_header=true \
    -s /opt/proxy/sni_passthrough.py \
    --mode reverse:https://10.0.2.10:443@8443 \
    --mode reverse:https://10.0.2.11:443@8444 \
    --mode reverse:https://10.0.2.12:443@8445

./trust.sh mitm_baseline                # zdaj Caddy + mitmproxy

clab exec -t ../mitm_baseline.clab.yml --label clab-node-name=client \
    --cmd "SSLKEYLOGFILE=/opt/traffic/out/keys.log python3 -m runner --config /opt/traffic/scenario.yml --duration 30"
```

Isti `mitmdump` ukaz velja za vse postavitve s posrednikom, spremeni se le ime vozlišča
(`clab-<topologija>-mitm`). Vrata 8443/8444/8445 ustrezajo pravilom `iptables` v topologiji,
ki preusmerijo promet za 10.0.2.10/11/12.

Dnevnik posrednika:

```sh
docker logs -f clab-mitm_baseline-mitm
```

### Stanje postavitve

```sh
clab inspect --all                                  # vsa vozlišča vseh topologij
clab inspect -t client_server.clab.yml
docker exec clab-client_server-client ip -br addr    # so se exec ukazi topologije izvedli?
```

## Zajem prometa

```sh
cd common
./capture.sh client_server client          # privzeto vmesnik eth1
./capture.sh client_server server eth1
./capture.sh --stop client_server client
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
cd common
# v scenario.yml spremeni testset.set
./gen_caddyfile.py
clab exec -t ../client_server.clab.yml --label clab-node-name=server \
    --cmd "caddy reload --config /opt/traffic/server/Caddyfile"
```

`gen_caddyfile.py` se da pognati tudi nad drugačnim scenarijem:

```sh
./gen_caddyfile.py --config tests/scenario.local.yml -o /tmp/sites.caddy
```

## Pospravljanje

```sh
cd common
rm -rf out/*                       # meritve, pcap, keys.log
rm -f pki/trust.pem
```

Vsebina `out/` nastane v kontejnerju kot root, a jo je vseeno mogoče pobrisati brez sudo,
ker je imenik last uporabnika. Če je iz starejšega zagona ostal še imenik `pki/caddy`
(nastal je, ko je Caddy hranil CA pod `/opt/traffic/pki`), ga odstrani prek kontejnerja,
ker ima pravice 0700 in root lastništvo:

```sh
docker run --rm -v "$PWD/pki:/w" server:latest rm -rf /w/caddy
```

Novejše postavitve tega imenika ne delajo več — Caddy hrani CA v `/data` znotraj
kontejnerja (privzetek slike `caddy:2`), `trust.sh` pa ga pobere z `docker exec`.

## Struktura

```
common/
  build_testset.py    LNU-Phish -> server/testset/<nabor>/
  gen_caddyfile.py    testni nabor -> server/sites.caddy
  build.sh            zgradi slike
  trust.sh            sestavi pki/trust.pem
  capture.sh          tcpdump v clab vozlu
  scenario.yml        odjemalci, profili, naslovi
  client/             slika odjemalca in runner/
  server/             slika streznika in Caddyfile
  proxy/              slika mitmproxy in sni_passthrough.py
  tests/              test_unit_*.py enotski testi, integration*.sh scenarija
```