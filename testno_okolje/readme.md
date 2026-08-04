# Testno okolje

## Primeri

Primerjamo štiri različne primere:

### p4_baseline

Ves promet med odjemalcem in strežnikom potuje prek stikala p4, ki pa ta promet zgolj posreduje.

client -- p4 -- server

Namen: za ugotavljanje osnovnih vrednosti pri meritvah

### mitm_full

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


### p4_controller

Ves promet pride do stikala p4, ki pa je glede na pravila (controller) posredovan direktno na cilj, prek mitm proxy-ja oziroma je promet posredovan direktno in je kopija prometa posredovana na suricato. V primeru zaznave nedovoljenega prometa se zmanjša stopnja zaupanja odjemalca in posledično gre naslednjič promet prek mitm proxy-ja.

        controller
           |
client -- p4 -- server
           + mitm_proxy
           + suricata


Namen: naša rešitev


