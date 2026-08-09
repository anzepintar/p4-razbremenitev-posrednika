from runner import summarize


def rows():
    return [
        {"proto": "h2", "category": "benign", "client": "c1", "trust": "high", "http_version": "2",
         "http_code": 200, "time_total": 0.010, "size_download": 100},
        {"proto": "h2", "category": "benign", "client": "c1", "trust": "high", "http_version": "2",
         "http_code": 200, "time_total": 0.020, "size_download": 200},
        {"proto": "h3", "category": "blocked", "client": "c3", "trust": "low", "http_version": "3",
         "http_code": 200, "time_total": 0.030, "size_download": 300},
        {"proto": "h3", "category": "blocked", "client": "c3", "trust": "low", "http_version": "3",
         "http_code": 500, "time_total": 0.040, "size_download": 0},
    ]


def test_percentile_uses_nearest_rank():
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert summarize.percentile(values, 50) == 5
    assert summarize.percentile(values, 95) == 10
    assert summarize.percentile(values, 100) == 10
    assert summarize.percentile([], 50) is None


def test_totals_count_errors_separately():
    total = summarize.summarize(rows())["total"]
    assert total == {
        "requests": 4,
        "ok": 3,
        "errors": 1,
        "blocked": 0,
        "bytes": 600,
        "p50_ms": 20.0,
        "p95_ms": 30.0,
        "p99_ms": 30.0,
    }


def test_blocked_counted_apart_from_errors():
    blocked = dict(rows()[0], http_code=403, blocked=True, block_rules="testset_label")
    total = summarize.summarize([*rows(), blocked])["total"]
    assert (total["requests"], total["ok"], total["errors"], total["blocked"]) == (5, 3, 2, 1)


def test_breakdown_by_every_grouping():
    summary = summarize.summarize(rows())
    assert summary["proto"]["h2"]["requests"] == 2
    assert summary["category"]["blocked"]["errors"] == 1
    assert summary["client"]["c1"]["ok"] == 2
    assert summary["http_version"]["3"]["requests"] == 2
    assert summary["trust"]["high"]["ok"] == 2
    assert summary["trust"]["low"]["p50_ms"] == 30.0


def test_percentiles_ignore_failed_requests():
    assert summarize.summarize(rows())["proto"]["h3"]["p50_ms"] == 30.0
