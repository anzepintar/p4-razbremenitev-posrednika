from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

PROTOCOLS = ("h2", "h3")
INDEX = "/index.html"

# Oznaki iz nabora LNU-Phish.
LABELS = {"ben": "legit", "mal": "phishing"}


class ScenarioError(ValueError):
    pass


@dataclass(frozen=True)
class Site:
    domain: str
    label: str
    ip: str

    @property
    def category(self) -> str:
        return LABELS[self.label]


@dataclass(frozen=True)
class Profile:
    name: str
    protocols: dict[str, float]
    labels: tuple[str, ...]
    rate: float
    think_time: tuple[float, float]
    fronting_share: float = 0.0


@dataclass(frozen=True)
class Client:
    id: str
    src_ip: str
    trust: str
    profile: str


@dataclass(frozen=True)
class Run:
    duration: float
    seed: int
    out: Path
    cacert: Path
    testset: Path
    subset: str
    max_subresources: int

    @property
    def root(self) -> Path:
        return self.testset / self.subset


@dataclass(frozen=True)
class Scenario:
    sites: dict[str, Site]
    clients: tuple[Client, ...]
    profiles: dict[str, Profile]
    run: Run

    def domains_by_ip(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for site in self.sites.values():
            grouped.setdefault(site.ip, []).append(site.domain)
        return {ip: sorted(names) for ip, names in sorted(grouped.items())}

    def by_label(self, label: str) -> list[Site]:
        return sorted((s for s in self.sites.values() if s.label == label), key=lambda s: s.domain)

    def profile_for(self, client: Client) -> Profile:
        return self.profiles[client.profile]

    def page_file(self, domain: str) -> Path:
        return self.run.root / domain / "index.html"


def assign_ips(domains: list[str], ips: list[str]) -> dict[str, str]:
    return {domain: ips[index % len(ips)] for index, domain in enumerate(sorted(domains))}


def load_sites(manifest: Path, ips: list[str]) -> dict[str, Site]:
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    mapping = assign_ips([entry["domain"] for entry in raw], ips)
    return {
        entry["domain"]: Site(
            domain=entry["domain"],
            label=entry["label"],
            ip=mapping[entry["domain"]],
        )
        for entry in raw
    }


def load(path: str | Path, *, testset: str | Path | None = None) -> Scenario:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    run, ips = _load_run(raw["run"], raw["testset"], testset)
    sites = load_sites(run.root / "sites.json", ips)
    profiles = _load_profiles(raw["profiles"], sites)
    clients = _load_clients(raw["clients"], profiles)
    return Scenario(sites=sites, clients=clients, profiles=profiles, run=run)


def _load_run(raw: dict, testset_cfg: dict, override: str | Path | None) -> tuple[Run, list[str]]:
    path = override if override is not None else testset_cfg["path"]
    run = Run(
        duration=float(raw.get("duration", 60)),
        seed=int(raw.get("seed", 0)),
        out=Path(raw.get("out", "/opt/traffic/out")),
        cacert=Path(raw.get("cacert", "/opt/traffic/pki/trust.pem")),
        testset=Path(path),
        subset=testset_cfg["set"],
        max_subresources=int(raw.get("max_subresources", 25)),
    )
    if not run.root.is_dir():
        raise ScenarioError(f"nabora '{run.subset}' ni v {run.testset}")
    return run, list(testset_cfg["ips"])


def _load_profiles(raw: dict, sites: dict[str, Site]) -> dict[str, Profile]:
    present = {site.label for site in sites.values()}

    profiles: dict[str, Profile] = {}
    for name, entry in raw.items():
        labels = tuple(entry["labels"])
        missing = set(labels) - present
        if missing:
            raise ScenarioError(f"profil '{name}': v naboru ni oznak {sorted(missing)}")

        unknown = set(entry["protocols"]) - set(PROTOCOLS)
        if unknown:
            raise ScenarioError(f"profil '{name}': neznani protokoli {sorted(unknown)}")

        think = entry["think_time"]
        profiles[name] = Profile(
            name=name,
            protocols={key: float(value) for key, value in entry["protocols"].items()},
            labels=labels,
            rate=float(entry["rate"]),
            think_time=(float(think[0]), float(think[1])),
            fronting_share=float(entry.get("fronting", {}).get("share", 0.0)),
        )
    return profiles


def _load_clients(raw: list, profiles: dict[str, Profile]) -> tuple[Client, ...]:
    clients = []
    for entry in raw:
        if entry["profile"] not in profiles:
            raise ScenarioError(f"odjemalec '{entry['id']}': neznan profil '{entry['profile']}'")
        clients.append(
            Client(
                id=entry["id"],
                src_ip=entry["src_ip"],
                trust=entry["trust"],
                profile=entry["profile"],
            )
        )
    return tuple(clients)
