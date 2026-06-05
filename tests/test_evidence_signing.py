from avvp.services.evidence_store.store import EvidenceStore
from avvp.services.evidence_store.signer import EvidenceSigner


def test_signing_local(tmp_path):
    es = EvidenceStore(out_dir=str(tmp_path))
    signer = EvidenceSigner()
    es.attach_signer(signer)
    data = b'some important evidence'
    res = es.save_evidence(data, {'name': 'signed.bin'})
    assert 'signature' in res
    # signature should be hex string
    assert isinstance(res['signature'], str)


def test_signer_public_key():
    s = EvidenceSigner()
    pem = s.public_key_pem()
    assert b'BEGIN PUBLIC KEY' in pem
