#!/usr/bin/env python3
from __future__ import annotations

import binascii
import json
import os
import sys
import time
from pathlib import Path

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoPair

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/out/quic_initials.json")
KEEP = "posnet_"
VERSION = 1
DCID = bytes.fromhex("8394c8f03e515708")
SCID = bytes.fromhex("0102030405060708")


def varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1073741824:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def client_hello(host: str, filler: int = 0) -> bytes:
    names = host.encode()
    entry = b"\x00" + len(names).to_bytes(2, "big") + names
    server_name = b"\x00\x00" + (len(entry) + 2).to_bytes(2, "big") \
        + len(entry).to_bytes(2, "big") + entry
    padding = b"\x00\x15" + filler.to_bytes(2, "big") + b"\x00" * filler
    extensions = padding + server_name if filler else server_name
    body = (
        b"\x03\x03" + b"\xaa" * 32 + b"\x00"
        + b"\x00\x02\x13\x01" + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def initial(crypto_offset: int, chunk: bytes, number: int = 0, pad: int = 0) -> bytes:
    payload = b"\x06" + varint(crypto_offset) + varint(len(chunk)) + chunk
    payload += b"\x00" * pad

    pair = CryptoPair()
    pair.setup_initial(cid=DCID, is_client=True, version=VERSION)
    length = len(payload) + pair.aead_tag_size + 1
    header = (
        b"\xc0" + VERSION.to_bytes(4, "big")
        + bytes([len(DCID)]) + DCID + bytes([len(SCID)]) + SCID
        + varint(0) + varint(length) + bytes([number])
    )
    return pair.encrypt_packet(header, payload, number)


def from_aioquic(host: str) -> list[bytes]:
    config = QuicConfiguration(is_client=True, server_name=host, alpn_protocols=["h3"])
    config.verify_mode = 0
    connection = QuicConnection(configuration=config)
    connection.connect(("10.0.2.10", 443), now=time.time())
    return [data for data, _ in connection.datagrams_to_send(now=time.time())]


def main() -> int:
    long_name = "a" * 59 + ".com"
    over_name = "b" * 60 + ".com"
    hello = client_hello("razdeljen.example")
    half = len(hello) // 2

    cases = {
        "aioquic": {"sni": "primer.com", "datagrams": from_aioquic("primer.com")},
        "aioquic_long": {"sni": long_name, "datagrams": from_aioquic(long_name)},
        "aioquic_over": {"sni": None, "datagrams": from_aioquic(over_name)},
        "kratek": {"sni": "primer.com", "datagrams": [initial(0, client_hello("primer.com"))]},
        "pozna_razsiritev": {
            "sni": "primer.com",
            "datagrams": [initial(0, client_hello("primer.com", filler=700))],
        },
        "razdeljen": {
            "sni": "razdeljen.example",
            "datagrams": [initial(0, hello[:half]), initial(half, hello[half:], number=1)],
        },
        "razdeljen_obrnjen": {
            "sni": "razdeljen.example",
            "datagrams": [initial(half, hello[half:], number=1), initial(0, hello[:half])],
        },
        "s_polnilom": {
            "sni": "primer.com",
            "datagrams": [initial(0, client_hello("primer.com"), pad=900)],
        },
        "brez_sni": {"sni": None, "datagrams": [initial(0, client_hello(""))]},
        "smeti": {"sni": None, "datagrams": [os.urandom(1200)]},
        "kratek_datagram": {"sni": None, "datagrams": [b"\xc0\x00\x00\x00\x01\x08"]},
    }

    data = {}
    if OUT.is_file():
        data = {
            name: case
            for name, case in json.loads(OUT.read_text(encoding="utf-8")).items()
            if name.startswith(KEEP)
        }
    data.update({
        name: {"sni": case["sni"],
               "datagrams": [binascii.hexlify(d).decode() for d in case["datagrams"]]}
        for name, case in cases.items()
    })
    OUT.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8")
    print(f"{OUT}: {len(data)} primerov")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
