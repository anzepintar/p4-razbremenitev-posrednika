# Testno okolje

## Postavitve

Štiri postavitve po dveh oseh: s stikalom P4 ali brez njega, ter proti lokalnemu strežniku
s testnim naborom ali proti pravemu spletu prek prehoda.

| postavitev | pot | namen |
| :--- | :--- | :--- |
| `mitm_server` | client — mitm — server | meritev: ves promet prek posrednika |
| `p4_mitm_server` | client — p4 — mitm — server | meritev: P4 usmeri prek posrednika le nizko zaupanje |
| `mitm_internet` | client — mitm — gateway → splet | ročno testiranje na resničnih straneh |
| `p4_mitm_internet` | client — p4 — mitm — gateway → splet | ročno testiranje na resničnih straneh |

```
mitm_server / mitm_internet        p4_mitm_server / p4_mitm_internet

client -- mitm -- server|gateway   client -- p4 -- server|gateway
                                              |
                                             mitm
```

Posrednik teče v **transparentnem** načinu (`--mode transparent@8080`): QUIC (UDP/443)
prestreže prek TPROXY, TCP/443 pa prek `REDIRECT` in `SO_ORIGINAL_DST`. Prestrezanje
QUIC-a doda fork mitmproxy iz `05-MITMPROXY-FORK/mitmproxy`.

Pri postavitvah s stikalom vnose v tabelo `steering` ob zagonu zapiše
`common/proxy/steer.py`, ki teče v vsebniku posrednika in se prek P4Runtime
(gRPC 10.20.1.2:9559) poveže na stikalo. Ločenega krmilnika ni.

Kaj gre prek posrednika, določa stopnja zaupanja odjemalca v `common/scenario.yml`:

```yaml
clients:
  - {id: c1, src_ip: 10.0.1.10, trust: high, profile: office}
  - {id: c2, src_ip: 10.0.1.11, trust: medium, profile: browsing}
  - {id: c3, src_ip: 10.0.1.12, trust: low, profile: suspicious}

steering: {high: direct, medium: direct, low: via_mitm}
```

Brez stikala te izbire ni — posrednik je vrinjen v pot in vidi ves promet. Prav ta razlika
je predmet primerjave.

Vrata bmv2 so fiksna: 1 = odjemalec, 2 = strežnik oziroma prehod, 3 = posrednik. `eth4`
stikala je le upravljalna pot do posrednika in ni del cevovoda P4.

## Namestitev

Vsi ukazi tečejo iz imenika testno_okolje. Gradnja potrebuje fork mitmproxy; privzeto ga
išče v `../../05-MITMPROXY-FORK/mitmproxy`, drugo pot podaš z `MITM_SRC`.

```sh
./common/build_testset.py
./common/build.sh
```

Slika `mitmproxy-quic:latest` se zgradi le, če je še ni. Po spremembi forka:

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
./common/measure.sh latency "mitm_server p4_mitm_server" 40 # zahtev na odjemalni IP
./common/measure.sh latency "mitm_server p4_mitm_server" 40 --content-block
```

## Meritev nasičenja

```sh
./common/measure.sh ramp "mitm_server p4_mitm_server" "1 2 4 8 16"
./common/measure.sh ramp "mitm_server p4_mitm_server" "1 2 4 8 16" --content-block
```

## Grafi in rezultati

```sh
./common/plot.py
```

## Ročno testiranje na spletu

```sh
./common/start.sh p4_mitm_internet
docker exec clab-p4_mitm_internet-client curl --http3-only \
	--cacert /opt/traffic/pki/trust.pem https://quic.anzepintar.com/
sudo clab destroy -t p4_mitm_internet.clab.yml --cleanup
```

Kontrolno zahtevo ob zagonu nastaviš s `PROBE_URL`. Prestrežene zahteve so v
`common/out/proxy_flows.jsonl`, dnevnik posrednika v `common/out/mitm.log`.

## Zagon brez sudo

```sh
SUDO= common/measure.sh latency mitm_server 40
SUDO= common/start.sh p4_mitm_server
```

## Ročni zagon postavitve

```sh
./common/start.sh p4_mitm_server --content-block
sudo clab destroy -t p4_mitm_server.clab.yml --cleanup
```

## Čiščenje

```sh
rm -rf common/out/*
rm -f common/pki/trust.pem
```
