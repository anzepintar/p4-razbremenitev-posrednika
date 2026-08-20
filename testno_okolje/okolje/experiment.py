from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "experiment.yml"
ASSIGNMENT = HERE / "lists" / "assignment.json"

GROUPS = ("ip_black", "ip_white", "sni_black", "sni_white", "content_block", "unknown")

MODES = ("brez", "ip_black", "ip_white", "sni_black", "sni_white", "content_block")
POLICY_MODES = tuple(mode for mode in MODES if mode != "brez")

CONTENT_MARKER = "x-block-me-7f3a"

BIG_OBJECT = "big.bin"


class ExperimentError(ValueError):
    pass


@dataclass(frozen=True)
class Experiment:
    groups: dict[str, int]
    server_ips: dict[str, str]
    protocols: dict[str, float]
    modes: list[str]
    connect_timeout_s: float
    max_time_s: float
    object_kb: int
    seed: int
    out: Path
    cacert: Path
    testset: Path
    subset: str
    total: int

    @property
    def root(self) -> Path:
        return self.testset / self.subset

    def ip_for(self, group: str) -> str:
        return self.server_ips.get(group, self.server_ips["default"])

def load(path: str | Path | None = None) -> Experiment:
    raw = yaml.safe_load(Path(path or CONFIG).read_text(encoding="utf-8"))

    domains = raw["domains"]
    groups = dict(domains["groups"])
    total = int(domains["total"])
    if sum(groups.values()) > total:
        raise ExperimentError(
            f"vsota skupin {sum(groups.values())} presega total {total}"
        )

    load_cfg = raw["load"]
    run = raw["run"]

    protocols = {str(k): float(v) for k, v in raw["protocols"].items()}
    bad_share = [k for k, v in protocols.items() if not 0.0 <= v <= 1.0]
    if bad_share:
        raise ExperimentError(
            f"protocols: delez HTTP/3 mora biti med 0 in 1, ni pa pri "
            f"{', '.join(bad_share)}"
        )

    default_modes = ["brez"] + [m for m in POLICY_MODES if groups.get(m)]
    modes = [str(m) for m in raw.get("modes", default_modes)]
    unknown_modes = [m for m in modes if m not in MODES]
    if unknown_modes:
        raise ExperimentError(
            f"modes pozna samo {', '.join(MODES)}, dobil pa "
            f"{', '.join(unknown_modes)}"
        )
    missing = [m for m in modes if m != "brez" and not groups.get(m)]
    if missing:
        raise ExperimentError(
            f"nacini {', '.join(missing)} nimajo domen; postavi domains.groups v "
            "experiment.yml na vec kot 0 in pozeni gen_lists.py"
        )

    return Experiment(
        groups=groups,
        server_ips=dict(raw["server_ips"]),
        protocols=protocols,
        modes=modes,
        connect_timeout_s=float(load_cfg.get("connect_timeout_s", 5)),
        max_time_s=float(load_cfg.get("max_time_s", 10)),
        object_kb=int(load_cfg.get("object_kb", 0)),
        seed=int(run["seed"]),
        out=Path(run["out"]),
        cacert=Path(run["cacert"]),
        testset=Path(run["testset"]),
        subset=str(run["subset"]),
        total=total,
    )


def available(experiment: Experiment, testset: Path | None = None) -> list[str]:
    root = (testset / experiment.subset) if testset else experiment.root
    if not root.is_dir():
        raise ExperimentError(f"nabora ni v {root}")
    names = [p.name for p in root.iterdir() if p.is_dir()]
    return sorted(names, key=lambda d: hashlib.sha1(d.encode()).hexdigest())


def assign(experiment: Experiment, domains: list[str]) -> dict[str, str]:
    if len(domains) < sum(experiment.groups.values()):
        raise ExperimentError(
            f"nabor ima {len(domains)} domen, skupine terjajo "
            f"{sum(experiment.groups.values())}"
        )

    result: dict[str, str] = {}
    position = 0
    for group in sorted(experiment.groups):
        count = experiment.groups[group]
        for domain in domains[position : position + count]:
            result[domain] = group
        position += count
    for domain in domains[position:]:
        result[domain] = "unknown"
    return result


def build(experiment: Experiment, testset: Path | None = None) -> dict:
    domains = available(experiment, testset)[: experiment.total]
    groups = assign(experiment, domains)
    return {
        "seed": experiment.seed,
        "subset": experiment.subset,
        "server_ips": experiment.server_ips,
        "counts": {
            group: sum(1 for g in groups.values() if g == group)
            for group in sorted(set(groups.values()))
        },
        "domains": {
            domain: {"group": group, "ip": experiment.ip_for(group)}
            for domain, group in sorted(groups.items())
        },
    }


def write_assignment(data: dict, path: Path | None = None) -> Path:
    target = Path(path or ASSIGNMENT)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def read_assignment(path: Path | None = None) -> dict:
    target = Path(path or ASSIGNMENT)
    if not target.is_file():
        raise ExperimentError(f"razdelitve ni v {target}; pozeni gen_lists.py")
    return json.loads(target.read_text(encoding="utf-8"))


def by_group(assignment: dict) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for domain, info in assignment["domains"].items():
        grouped.setdefault(info["group"], []).append(domain)
    return {group: sorted(names) for group, names in grouped.items()}
