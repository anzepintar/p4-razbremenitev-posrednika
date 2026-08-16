from __future__ import annotations

from dataclasses import dataclass

from .scenario import BIG, INDEX, Scenario


@dataclass(frozen=True)
class Target:
    domain: str
    path: str

    @property
    def url(self) -> str:
        return f"https://{self.domain}{self.path}"


def page_targets(scenario: Scenario, domain: str) -> list[Target]:
    path = BIG if scenario.run.object_kb else INDEX
    return [Target(domain=domain, path=path)]
