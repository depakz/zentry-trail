from avvp.services.diff_analyzer.analyzer import analyze


def test_analyze_no_baseline():
    res = analyze(None, {'status_code':200, 'body':'ok', 'latency':10})
    assert res.anomaly_score == 1.0


def test_analyze_status_change():
    base = {'status_code':200, 'body':'ok', 'latency':10}
    resp = {'status_code':500, 'body':'error', 'latency':30}
    res = analyze(base, resp)
    assert res.anomaly_score > 0
