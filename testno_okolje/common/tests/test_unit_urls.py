from runner import urls
from runner.urls import Target


def test_subresource_limit_is_honoured(scenario):
    limit = scenario.run.max_subresources
    for domain in sorted(scenario.sites):
        assert len(urls.page_targets(scenario, domain)) <= limit + 1


def test_extract_refs_picks_subresources_not_navigation():
    html = """
    <link rel="stylesheet" href="/a.css">
    <link rel="canonical" href="/ignore-me">
    <script src="/b.js"></script>
    <img src="/c.png">
    <a href="/page.html">nav</a>
    """
    assert urls.extract_refs(html) == ["/a.css", "/b.js", "/c.png"]


def test_resolve():
    assert urls.resolve("https://cdn.example/x.js", "a.example", "/index.html") == Target(
        "cdn.example", "/x.js"
    )
    assert urls.resolve("/s/app.css", "a.example", "/index.html") == Target(
        "a.example", "/s/app.css"
    )
    assert urls.resolve("x.css", "a.example", "/dir/b.html") == Target("a.example", "/dir/x.css")
    assert urls.resolve("https://a.example:8443/x", "b.example", "/i.html") == Target(
        "a.example", "/x"
    )
    assert urls.resolve("//cdn.example/x.js", "a.example", "/i.html") == Target(
        "cdn.example", "/x.js"
    )


def test_resolve_skips_other_schemes():
    assert urls.resolve("data:text/css,body{}", "a.example", "/i.html") is None
    assert urls.resolve("#anchor", "a.example", "/i.html") is None
    assert urls.resolve("", "a.example", "/i.html") is None
