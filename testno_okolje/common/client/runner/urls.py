from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from posixpath import normpath
from urllib.parse import urlsplit

from .scenario import INDEX, Scenario

SUBRESOURCE_RELS = {"stylesheet", "icon", "shortcut icon", "preload", "prefetch"}


@dataclass(frozen=True)
class Target:
    domain: str
    path: str

    @property
    def url(self) -> str:
        return f"https://{self.domain}{self.path}"


class _RefParser(HTMLParser):

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "link":
            rel = (attr.get("rel") or "").strip().lower()
            if rel in SUBRESOURCE_RELS and attr.get("href"):
                self.refs.append(attr["href"])
        elif tag in ("script", "img") and attr.get("src"):
            self.refs.append(attr["src"])


def extract_refs(html: str) -> list[str]:
    parser = _RefParser()
    parser.feed(html)
    parser.close()
    return parser.refs


def resolve(ref: str, base_domain: str, base_path: str) -> Target | None:
    ref = ref.strip()
    if not ref or ref.startswith("#"):
        return None
    parts = urlsplit(ref)
    if parts.scheme and parts.scheme not in ("http", "https"):
        return None

    if parts.netloc:
        domain, path = parts.netloc.split(":")[0].lower(), parts.path or "/"
    elif ref.startswith("/"):
        domain, path = base_domain, parts.path
    else:
        base_dir = base_path.rsplit("/", 1)[0]
        domain, path = base_domain, normpath(f"{base_dir}/{parts.path}")
    return Target(domain=domain, path=path or "/")


def page_targets(scenario: Scenario, domain: str) -> list[Target]:
    targets = [Target(domain=domain, path=INDEX)]
    html = scenario.page_file(domain).read_text(encoding="utf-8", errors="replace")

    limit = scenario.run.max_subresources
    seen = set(targets)
    for ref in extract_refs(html):
        if len(targets) > limit:
            break
        target = resolve(ref, domain, INDEX)
        if target is None or target in seen or target.domain not in scenario.sites:
            continue
        seen.add(target)
        targets.append(target)
    return targets
