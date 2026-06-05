from fastapi.testclient import TestClient
from avvp.api.main import app
from avvp.services.evidence_store.signer import EvidenceSigner
from avvp.services.evidence_store.store import EvidenceStore
import io

client = TestClient(app)

def test_health():
    r = client.get('/health')
    assert r.status_code == 200
    assert r.json()['status'] == 'ok'

def test_payloads_list():
    r = client.get('/payloads')
    assert r.status_code == 200
    payload = r.json()
    assert 'templates' in payload
    assert 'categories' in payload
    assert 'count' in payload
    assert payload['count'] >= len(payload['templates'])

def test_evidence_upload(tmp_path):
    # override store to use tmp path for deterministic test
    store = EvidenceStore(out_dir=str(tmp_path))
    signer = EvidenceSigner()
    store.attach_signer(signer)
    # monkeypatch app STORE
    from avvp.api import main as m
    m.STORE = store
    data = b'test-upload'
    files = {'file': ('test.bin', io.BytesIO(data), 'application/octet-stream')}
    resp = client.post('/evidence/upload', data={'name':'test.bin'}, files=files)
    assert resp.status_code == 200
    j = resp.json()
    assert 'location' in j and 'signature' in j

def test_report_generate(tmp_path):
    from avvp.api import main as m
    m.REPORTER = m.REPORTER.__class__(out_dir=str(tmp_path))
    findings = {'findings': [{'message':'x','severity':'low'}]}
    r = client.post('/report/generate', json=findings)
    assert r.status_code == 200
    j = r.json()
    assert 'sarif' in j and 'html' in j
