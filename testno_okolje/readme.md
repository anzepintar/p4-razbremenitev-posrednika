# Testno okolje

## Primeri

Primerjamo sedem različnih primerov:

### client_server

Samo odjemalec in strežnik, brez stikala in posrednika.

client -- server

Namen: potrditev, da odjemalec in strežnik delujeta, ločeno od vsega ostalega.

### mitm_baseline

Ves promet med odjemalcem in strežnikom gre preko mitmproxy-ja.

client -- mitm proxy -- server

Namen: osnovni primer s katerim se naša rešitev primerja, mora biti vsaj boljša od tega.

Posrednik promet le prestreže in posreduje naprej. Z zastavico --content-block pregleda tudi
vsebino strani in phishing blokira.

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

Vsi ukazi tečejo iz imenika testno_okolje.

```sh
./common/build_testset.py
./common/build.sh
```

## Nabor testnih primerov

```sh
./common/subset.sh osnovni
./common/subset.sh testni
```

## Meritev latence in hitrosti

```sh
./common/measure.sh latency "client_server mitm_baseline p4_baseline p4_full" 40 # število zahtev na odjemalni IP
./common/measure.sh latency "client_server mitm_baseline p4_baseline p4_full" 40 --content-block
```

## Meritev nasičenja

```sh
./common/measure.sh ramp "client_server mitm_baseline p4_baseline p4_full" "1 2 4 8 16"
./common/measure.sh ramp "client_server mitm_baseline p4_baseline p4_full" "1 2 4 8 16" --content-block
```

## Grafi in rezultati

```sh
./common/plot.py
```

## Zagon brez sudo

```sh
SUDO= common/measure.sh latency p4_full 40
SUDO= common/start.sh p4_full
```

## Ročni zagon postavitve

```sh
./common/start.sh p4_full --content-block
sudo clab destroy -t p4_full.clab.yml --cleanup
```

## Čiščenje

```sh
rm -rf common/out/*
rm -f common/pki/trust.pem
```
