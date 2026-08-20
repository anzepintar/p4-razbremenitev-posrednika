from __future__ import annotations

import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

PROTOCOLS = ("h2", "h3")
INDEX = "/index.html"
BIG = "/big.bin"

COMMON = Path("/opt/traffic")

GROUPS = (
    "ip_black", "ip_white", "sni_black", "sni_white", "content_block", "unknown",
)

BLOCKED_GROUPS = ("ip_black", "sni_black", "content_block")


class ScenarioError(ValueError):
    pass


@dataclass(frozen=True)
class Site:
    domain: str
    group: str
    ip: str

    @property
    def expect_blocked(self) -> bool:
        return self.group in BLOCKED_GROUPS


@dataclass(frozen=True)
class Run:
    seed: int
    out: Path
    cacert: Path
    testset: Path
    subset: str
    connect_timeout_s: float
    max_time_s: float
    object_kb: int

    @property
    def root(self) -> Path:
        return self.testset / self.subset


@dataclass(frozen=True)
class Scenario:
    sites: dict[str, Site]
    run: Run
    quic_share: float

    def domains(self) -> list[str]:
        return sorted(self.sites)

    def domains_in(self, groups: list[str]) -> list[str]:
        unknown = [g for g in groups if g not in GROUPS]
        if unknown:
            raise ScenarioError(
                f"skupine '{', '.join(unknown)}' ni; na voljo so {', '.join(GROUPS)}"
            )
        found = sorted(s.domain for s in self.sites.values() if s.group in groups)
        if not found:
            raise ScenarioError(
                f"razdelitev nima nobene domene iz skupin '{', '.join(groups)}'; "
                "popravi experiment.yml in pozeni gen_lists.py"
            )
        return found

    def by_group(self, group: str) -> list[Site]:
        return sorted(
            (s for s in self.sites.values() if s.group == group), key=lambda s: s.domain
        )

    def ip_for(self, domain: str) -> str:
        site = self.sites.get(domain)
        if site is None:
            raise ScenarioError(f"domene '{domain}' ni v razdelitvi")
        return site.ip

    def page_file(self, domain: str) -> Path:
        return self.run.root / domain / "index.html"

    @property
    def object_path(self) -> str:
        return BIG if self.run.object_kb else INDEX


@dataclass(frozen=True)
class Pool:
    domains: dict[str, list[str]]
    names: tuple[str, ...]
    weights: tuple[float, ...]

    def pick(self, rng: random.Random) -> str:
        group = (self.names[0] if len(self.names) == 1
                 else rng.choices(self.names, self.weights)[0])
        return rng.choice(self.domains[group])


def parse_groups(text: str | None) -> dict[str, float] | None:
    if not text:
        return None
    weighted: dict[str, float] = {}
    for part in text.split(","):
        name, _, weight = part.strip().partition(":")
        try:
            weighted[name.strip()] = float(weight) if weight else 1.0
        except ValueError:
            raise ScenarioError(f"utez '{weight}' pri skupini '{name}' ni stevilo")
    negative = [name for name, weight in weighted.items() if weight < 0]
    if negative:
        raise ScenarioError(f"utezi skupin {', '.join(negative)} so negativne")
    if not any(weighted.values()):
        raise ScenarioError("vse utezi skupin so nic")
    return weighted


def build_pool(scenario: Scenario, groups: dict[str, float] | None) -> Pool:
    if not groups:
        return Pool(domains={"": scenario.domains()}, names=("",), weights=(1.0,))
    domains = {name: scenario.domains_in([name])
               for name, weight in groups.items() if weight > 0}
    return Pool(domains=domains,
                names=tuple(domains),
                weights=tuple(groups[name] for name in domains))


def load(
    config: str | Path = COMMON / "experiment.yml",
    *,
    assignment: str | Path | None = None,
    quic_share: float | None = None,
    testset: str | Path | None = None,
) -> Scenario:
    sys.path.insert(0, str(Path(config).resolve().parent))
    import experiment as exp

    settings = exp.load(config)
    data = json.loads(
        Path(assignment or Path(config).parent / "lists" / "assignment.json")
        .read_text(encoding="utf-8")
    )

    sites = {
        domain: Site(domain=domain, group=info["group"], ip=info["ip"])
        for domain, info in data["domains"].items()
    }
    if not sites:
        raise ScenarioError("razdelitev je prazna; pozeni gen_lists.py")

    run = Run(
        seed=settings.seed,
        out=settings.out,
        cacert=settings.cacert,
        testset=Path(testset) if testset else settings.testset,
        subset=settings.subset,
        connect_timeout_s=settings.connect_timeout_s,
        max_time_s=settings.max_time_s,
        object_kb=settings.object_kb,
    )
    if not run.root.is_dir():
        raise ScenarioError(f"nabora '{run.subset}' ni v {run.testset}")

    share = quic_share if quic_share is not None else 0.0
    if not 0.0 <= share <= 1.0:
        raise ScenarioError(f"quic_share {share} ni med 0 in 1")

    return Scenario(sites=sites, run=run, quic_share=share)
