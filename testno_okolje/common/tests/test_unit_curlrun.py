from runner import curlrun
from runner.curlrun import Request
from runner.urls import Target


def one(scenario):
    return sorted(scenario.sites)[0]


def argv_for(scenario, **kwargs):
    default = Request(targets=(Target(one(scenario), "/index.html"),), proto="h2")
    request = kwargs.pop("request", default)
    kwargs.setdefault("src_ip", "10.0.1.11")
    kwargs.setdefault("cacert", "/opt/traffic/pki/trust.pem")
    return curlrun.build_argv(scenario, request, **kwargs)


def test_resolve_replaces_dns_but_keeps_domain_in_url(scenario):
    domain = one(scenario)
    argv = argv_for(scenario)
    assert argv[argv.index("--resolve") + 1] == f"{domain}:443:{scenario.sites[domain].ip}"
    # URL mora ostati domena, sicer SNI ne bi bil pravi.
    assert argv[-1] == f"https://{domain}/index.html"


def test_block_header_marks_row_as_blocked():
    record = {
        "curl": {"http_code": 403},
        "x_sni": "legit.example",
        "x_domain": "phish.example",
        "x_block": "testset_label,password_input",
    }
    row = curlrun.to_metric(record, labels={})
    assert (row["blocked"], row["block_rules"]) == (True, "testset_label,password_input")
    # Domena ostane phishing, SNI pa legitimna - blokada torej ni padla po SNI.
    assert (row["server_domain"], row["server_sni"]) == ("phish.example", "legit.example")


def test_row_without_block_header_is_not_blocked():
    row = curlrun.to_metric({"curl": {"http_code": 200}, "x_block": ""}, labels={})
    assert (row["blocked"], row["block_rules"]) == (False, None)


def test_host_header_only_when_fronting(scenario):
    assert "--header" not in argv_for(scenario)

    cover = scenario.by_label("ben")[0].domain
    hidden = scenario.by_label("mal")[0].domain
    fronted = Request(
        targets=(Target(cover, "/index.html"),), proto="h3", host_header=hidden
    )
    argv = argv_for(scenario, request=fronted)
    assert argv[argv.index("--header") + 1] == f"Host: {hidden}"
    # SNI pride iz URL-ja (legitimna domena), :authority pa iz glave (phishing).
    assert argv[-1].startswith(f"https://{cover}/")
