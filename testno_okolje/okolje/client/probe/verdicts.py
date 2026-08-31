"""Pravila, po katerih se poskus steje za uspesen, in gradnja ukazov.

Modul je namenoma brez stranskih ucinkov: enotski testi, prober v vsebniku in
porocilo na gostitelju berejo isto kodo, zato se merilo "deluje" ne more razhajati
med tem, kar se izmeri, in tem, kar se poroca.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from runner.curlrun import PROTO_FLAG

PROTOCOLS = ("h2", "h3")
CLIENTS = ("curl", "chromium", "firefox")

# Kar odjemalec poroca kot uporabljeni protokol, preslikano v nasi dve oznaki.
MEASURED = {"2": "h2", "3": "h3", "h2": "h2", "h3": "h3"}

# Chromiumova stran z omrezno napako in vmesna stran ob napaki potrdila.
CHROMIUM_ERROR_MARKS = ('id="main-frame-error"', 'id="interstitial-wrapper"')
CHROMIUM_ERROR_CODE = re.compile(r"ERR_[A-Z0-9_]+")
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Firefoxove strani z napako; razlog je v parametru e= naslova.
FIREFOX_ERROR_PAGES = ("about:neterror", "about:certerror", "about:blocked")
FIREFOX_ERROR_CODE = re.compile(r"[?&]e=([A-Za-z0-9_]+)")

# Stran 502, ki jo ob neuspeli povezavi navzgor vrne posrednik sam.
SERVER_ERROR_TITLE = re.compile(r"^\s*(5\d\d)\b")

CERT_SUBJECT = re.compile(r"^Subject:(.*)$", re.MULTILINE)
CERT_ISSUER = re.compile(r"^Issuer:(.*)$", re.MULTILINE)


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""


def origin_of(url: str) -> str:
    """Naslov oblike https://gostitelj/ - cilj, ki ga dobijo vsi odjemalci."""
    host = host_of(url)
    return f"https://{host}/" if host else ""


def curl_argv(url: str, proto: str, *, connect_timeout: float, max_time: float,
              cacert: str | None = None, follow: bool = False) -> list[str]:
    # --ipv4: krmiljenje.p4 zavrze vse, kar ni IPv4.
    argv = ["curl", "--silent", "--no-progress-meter", "--show-error", "--ipv4"]
    argv += ["--connect-timeout", f"{connect_timeout:g}", "--max-time", f"{max_time:g}"]
    argv += PROTO_FLAG[proto]
    if follow:
        argv += ["--location", "--max-redirs", "5"]
    if cacert:
        argv += ["--cacert", cacert]
    argv += ["--write-out", "%{json}", "--output", "/dev/null", url]
    return argv


def leaf_cert(certs: str | None) -> dict[str, str | None]:
    """Prva Subject in Issuer iz polja certs, torej potrdilo streznika."""
    if not certs:
        return {"subject": None, "issuer": None}
    subject = CERT_SUBJECT.search(certs)
    issuer = CERT_ISSUER.search(certs)
    return {
        "subject": subject.group(1).strip() if subject else None,
        "issuer": issuer.group(1).strip() if issuer else None,
    }


def server_error(http_code: object = None, title: str | None = None) -> str | None:
    """Oznaka napake, kadar je odgovor napaka streznika ali posrednika."""
    try:
        code = int(http_code or 0)
    except (TypeError, ValueError):
        code = 0
    if code >= 500:
        return f"http:{code}"
    found = SERVER_ERROR_TITLE.match(title or "")
    return f"http:{found.group(1)}" if found else None


def curl_verdict(record: dict, proto: str) -> dict:
    """Izid enega klica curl. Koda HTTP ni merilo, ker apex domene vracajo 301."""
    exitcode = record.get("exitcode")
    measured = MEASURED.get(str(record.get("http_version") or "").strip())
    verdict = {
        "ok": False,
        "protocol": measured,
        "http_code": record.get("http_code") or None,
        "url_effective": record.get("url_effective"),
        "ms": round((record.get("time_total") or 0) * 1000, 1) or None,
        "error": None,
        "message": None,
        **leaf_cert(record.get("certs")),
    }

    if exitcode:
        verdict["error"] = f"curl:{exitcode}"
        verdict["message"] = record.get("errormsg") or None
    elif measured != proto:
        verdict["error"] = "protokol"
        verdict["message"] = (
            f"zahtevan {proto}, odgovoril {record.get('http_version') or '?'}"
        )
    elif failure := server_error(verdict["http_code"]):
        verdict["error"] = failure
        verdict["message"] = "odgovor je napaka streznika ali posrednika"
    else:
        verdict["ok"] = True
    return verdict


def chromium_env(host: str, proto: str) -> dict[str, str]:
    """Okolje za browser/chromium.sh; zastavice ostanejo tam, na enem mestu.
    Vrata doda skripta sama, tako kot pri browse.sh."""
    if proto == "h3":
        return {"FORCE_QUIC": host, "NO_QUIC": ""}
    return {"FORCE_QUIC": "", "NO_QUIC": "1"}


def chromium_argv(url: str, *, budget_ms: int) -> list[str]:
    return [
        "--headless",
        "--disable-dev-shm-usage",
        f"--virtual-time-budget={budget_ms}",
        "--dump-dom",
        url,
    ]


def chromium_verdict(dom: str, *, proto: str, returncode: int = 0) -> dict:
    verdict = {"ok": False, "protocol": None, "http_code": None, "url_effective": None,
               "ms": None, "error": None, "message": None,
               "subject": None, "issuer": None,
               "title": None, "bytes": len(dom)}

    if not dom.strip():
        verdict["error"] = "prazen izpis"
        verdict["message"] = f"chromium se je koncal s kodo {returncode}"
        return verdict

    title = TITLE.search(dom)
    verdict["title"] = title.group(1).strip()[:120] if title else None

    if any(mark in dom for mark in CHROMIUM_ERROR_MARKS):
        code = CHROMIUM_ERROR_CODE.search(dom)
        verdict["error"] = code.group(0) if code else "stran z napako"
        verdict["message"] = verdict["title"]
        return verdict

    if failure := server_error(title=verdict["title"]):
        verdict["error"] = failure
        verdict["message"] = "odgovor je napaka streznika ali posrednika"
        return verdict

    # Protokol jamci zastavica: --disable-quic oziroma --origin-to-force-quic-on.
    verdict["ok"] = True
    verdict["protocol"] = proto
    return verdict


def firefox_env(hosts: list[str], proto: str, *, marionette_port: int,
                no_kyber: bool = False) -> dict[str, str]:
    """Okolje za browser/firefox.sh. FORCE_QUIC je seznam gostiteljev, locenih z
    vejico: vsiljeni h3 velja za tocno ime gostitelja, zato gredo v preslikavo
    koncni gostitelji ciljev in ne apex domene."""
    env = {"MARIONETTE_PORT": str(marionette_port), "FORCE_QUIC": "", "NO_QUIC": "",
           "NO_KYBER": "1" if no_kyber else ""}
    if proto == "h3":
        env["FORCE_QUIC"] = ",".join(hosts)
    else:
        env["NO_QUIC"] = "1"
    return env



def firefox_verdict(error: dict | None, value: list | None, proto: str) -> dict:
    """Izid ene navigacije. Firefox edini pove uporabljeni protokol neposredno,
    prek performance.getEntriesByType('navigation')[0].nextHopProtocol."""
    verdict = {"ok": False, "protocol": None, "http_code": None, "url_effective": None,
               "ms": None, "error": None, "message": None,
               "subject": None, "issuer": None, "title": None}

    if error:
        message = str(error.get("message") or "").replace("\n", " ")
        code = FIREFOX_ERROR_CODE.search(message)
        verdict["error"] = code.group(1) if code else str(error.get("error") or "napaka")
        verdict["message"] = message[:200] or None
        return verdict

    title, uri, hop = (list(value) + [None, None, None])[:3] if value else (None, None, None)
    verdict["title"] = (title or "").strip()[:120] or None
    verdict["url_effective"] = uri
    verdict["protocol"] = MEASURED.get(str(hop or "").strip(), (hop or None))

    if uri and any(uri.startswith(page) for page in FIREFOX_ERROR_PAGES):
        code = FIREFOX_ERROR_CODE.search(uri)
        verdict["error"] = code.group(1) if code else "stran z napako"
        verdict["message"] = uri[:200]
        return verdict

    if verdict["protocol"] != proto:
        verdict["error"] = "protokol"
        verdict["message"] = f"zahtevan {proto}, uporabljen {hop or '?'}"
        return verdict

    if failure := server_error(title=verdict["title"]):
        verdict["error"] = failure
        verdict["message"] = "odgovor je napaka streznika ali posrednika"
        return verdict

    verdict["ok"] = True
    return verdict
