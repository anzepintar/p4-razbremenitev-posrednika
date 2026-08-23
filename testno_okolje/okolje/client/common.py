"""Skupno za runner in probe, ki oba tecejo v vsebniku odjemalca."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path


class Writer:
    """Zapisovalnik vrstic JSONL, ki hkrati hrani zapisano v pomnilniku.

    Vrstice se sproti splaknejo, ker gostitelj datoteko bere se med tekom, hkrati
    pa jih klicatelj na koncu potrebuje za povzetek.
    """

    def __init__(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("w", encoding="utf-8")
        self._lock = asyncio.Lock()
        self.rows: list[dict] = []

    async def write(self, *rows: dict) -> None:
        async with self._lock:
            for row in rows:
                self._handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                self.rows.append(row)
            self._handle.flush()

    def close(self) -> None:
        self._handle.close()


def drain(queue: "asyncio.Queue"):
    """Vrsta do izpraznitve. Delavci tecejo v isti zanki, zato med preverjanjem
    in prevzemom ni tekmovanja."""
    while True:
        try:
            yield queue.get_nowait()
        except asyncio.QueueEmpty:
            return
