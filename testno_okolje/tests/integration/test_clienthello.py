from __future__ import annotations

import re

from conftest import P4, p4_const

EXT_SERVER_NAME = 0
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION = 65281
EXT_EC_POINT_FORMATS = 11


def p4_extension_slots() -> int:
    text = P4.read_text(encoding="utf-8")
    return len(re.findall(r"TLS_EXTENSION_SLOT\(\d+,", text))


MAX_EXT_BODY = p4_const("MAX_EXT_BODY")
MAX_SNI_NAME = p4_const("MAX_SNI_NAME")
MAX_SESSION_ID = p4_const("MAX_SESSION_ID")
MAX_CIPHERS = p4_const("MAX_CIPHERS")
SLOTS = p4_extension_slots()


def extension(etype: int, body: bytes) -> bytes:
    return etype.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def server_name(host: str) -> bytes:
    name = host.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    return extension(EXT_SERVER_NAME, len(entry).to_bytes(2, "big") + entry)


def client_hello(extensions: list[bytes], *, session_id: int = 32, ciphers: int = 60) -> bytes:
    body = (
        b"\x03\x03"
        + b"\xaa" * 32
        + bytes([session_id]) + b"\xbb" * session_id
        + ciphers.to_bytes(2, "big") + b"\x13\x02" * (ciphers // 2)
        + b"\x01\x00"
    )
    joined = b"".join(extensions)
    body += len(joined).to_bytes(2, "big") + joined
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def parse_sni(packet: bytes) -> str | None:
    try:
        return _parse_sni(packet)
    except IndexError:
        return None


def _parse_sni(packet: bytes) -> str | None:
    def need(offset: int) -> None:
        if offset > len(packet):
            raise IndexError(offset)

    if not packet or packet[0] != 0x16:
        return None
    p = 5
    need(p + 1)
    if packet[p] != 0x01:
        return None
    p += 4 + 2 + 32
    need(p + 1)

    session_len = packet[p]
    if session_len > MAX_SESSION_ID:
        return None
    p += 1 + session_len
    need(p + 2)

    cipher_len = int.from_bytes(packet[p:p + 2], "big")
    if cipher_len > MAX_CIPHERS:
        return None
    p += 2 + cipher_len
    need(p + 1)

    compression_len = packet[p]
    p += 1 + compression_len
    need(p + 2)

    ext_total = int.from_bytes(packet[p:p + 2], "big")
    if ext_total == 0:
        return None
    p += 2

    for _ in range(SLOTS):
        need(p + 4)
        etype = int.from_bytes(packet[p:p + 2], "big")
        elen = int.from_bytes(packet[p + 2:p + 4], "big")
        if etype == EXT_SERVER_NAME:
            need(p + 9)
            name_len = int.from_bytes(packet[p + 7:p + 9], "big")
            if packet[p + 6] != 0 or not 1 <= name_len <= MAX_SNI_NAME:
                return None
            need(p + 9 + name_len)
            return packet[p + 9:p + 9 + name_len].decode()
        if elen > MAX_EXT_BODY:
            return None
        p += 4 + elen
    return None


class TestKonstante:
    def test_sest_rez(self):
        assert SLOTS == 6

    def test_meje_iz_programa(self):
        assert (MAX_EXT_BODY, MAX_SNI_NAME, MAX_SESSION_ID) == (256, 63, 32)


class TestUjame:
    def test_sni_v_prvi_rezi(self):
        packet = client_hello([server_name("primer.com")])
        assert parse_sni(packet) == "primer.com"

    def test_sni_v_drugi_rezi_kot_pri_curl(self):
        packet = client_hello([
            extension(EXT_RENEGOTIATION, b"\x00"),
            server_name("primer.com"),
        ])
        assert parse_sni(packet) == "primer.com"

    def test_sni_v_zadnji_dovoljeni_rezi(self):
        fill = [extension(EXT_EC_POINT_FORMATS, b"\x01\x00")] * (SLOTS - 1)
        packet = client_hello([*fill, server_name("primer.com")])
        assert parse_sni(packet) == "primer.com"

    def test_ime_natanko_na_meji(self):
        host = "a" * (MAX_SNI_NAME - len(".com")) + ".com"
        assert len(host) == MAX_SNI_NAME
        assert parse_sni(client_hello([server_name(host)])) == host


class TestSpusti:
    def test_sni_cez_zadnjo_rezo(self):
        fill = [extension(EXT_EC_POINT_FORMATS, b"\x01\x00")] * SLOTS
        packet = client_hello([*fill, server_name("primer.com")])
        assert parse_sni(packet) is None

    def test_velika_razsiritev_pred_sni_ustavi_razclenjevanje(self):
        packet = client_hello([
            extension(EXT_KEY_SHARE, b"\x00" * (MAX_EXT_BODY + 1)),
            server_name("primer.com"),
        ])
        assert parse_sni(packet) is None

    def test_razsiritev_natanko_na_meji_se_preskoci(self):
        packet = client_hello([
            extension(EXT_KEY_SHARE, b"\x00" * MAX_EXT_BODY),
            server_name("primer.com"),
        ])
        assert parse_sni(packet) == "primer.com"

    def test_predolgo_ime(self):
        host = "a" * (MAX_SNI_NAME + 1)
        assert parse_sni(client_hello([server_name(host)])) is None

    def test_predolg_session_id(self):
        packet = client_hello([server_name("primer.com")], session_id=MAX_SESSION_ID + 1)
        assert parse_sni(packet) is None

    def test_ni_handshake(self):
        packet = bytearray(client_hello([server_name("primer.com")]))
        packet[0] = 0x17
        assert parse_sni(bytes(packet)) is None

    def test_razdrobljen_zapis(self):
        packet = client_hello([
            extension(EXT_RENEGOTIATION, b"\x00"),
            extension(EXT_EC_POINT_FORMATS, b"\x01\x00"),
            server_name("primer.com"),
        ])
        assert parse_sni(packet[: len(packet) // 2]) is None


class TestRazvrstitevPosiljateljev:

    CURL = [
        (EXT_RENEGOTIATION, 1),
        (EXT_SERVER_NAME, None),
    ]
    OPENSSL = [
        (EXT_RENEGOTIATION, 1),
        (EXT_EC_POINT_FORMATS, 2),
        (10, 24),
        (35, 0),
        (22, 0),
        (23, 0),
        (13, 56),
        (43, 5),
        (45, 2),
        (EXT_KEY_SHARE, 1258),
        (EXT_SERVER_NAME, None),
    ]

    def build(self, layout):
        parts = []
        for etype, size in layout:
            if etype == EXT_SERVER_NAME:
                parts.append(server_name("primer.com"))
            else:
                parts.append(extension(etype, b"\x00" * size))
        return client_hello(parts)

    def test_odjemalcev_hello_da_ime(self):
        assert parse_sni(self.build(self.CURL)) == "primer.com"

    def test_posrednikov_hello_ne_da_imena(self):
        assert parse_sni(self.build(self.OPENSSL)) is None

    def test_zakaj_odpove(self):
        slot = [etype for etype, _ in self.OPENSSL].index(EXT_SERVER_NAME)
        assert slot >= SLOTS
        before = [size for etype, size in self.OPENSSL if etype == EXT_KEY_SHARE][0]
        assert before > MAX_EXT_BODY
