import os
from avvp.services.evidence_store.store import EvidenceStore
from avvp.services.reporter.reporter import Reporter
from avvp.services.integrations.slack import SlackIntegration
from avvp.services.integrations.jira import JiraIntegration


def test_evidence_store(tmp_path):
    es = EvidenceStore(out_dir=str(tmp_path))
    data = b"hello-evidence"
    meta = {'name': 'test.bin'}
    res = es.save_evidence(data, meta)
    assert 'signature' in res
    assert 'location' in res
    # if local path, file should exist
    loc = res['location']
    if os.path.exists(loc):
        assert os.path.getsize(loc) > 0


def test_reporter(tmp_path):
    r = Reporter(out_dir=str(tmp_path))
    findings = [{'message': 'vuln1','severity':'high'}]
    s = r.write_sarif(findings, 'a.sarif.json')
    h = r.write_html(findings, 'a.html')
    assert os.path.exists(s)
    assert os.path.exists(h)


def test_integrations():
    s = SlackIntegration()
    assert s.send_message('test')['ok']
    j = JiraIntegration()
    assert j.create_issue('P', 'sum', 'desc')['ok']
