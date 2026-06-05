import io
from avvp.services.evidence_store.store import EvidenceStore
from avvp.services.evidence_store.signer import EvidenceSigner

class FakeMinio:
    def __init__(self):
        self.buckets = {}
        self.objects = {}
    def make_bucket(self, name):
        self.buckets[name] = True
    def put_object(self, bucket, object_name, data, length):
        # accept BytesIO or bytes
        if hasattr(data, 'read'):
            b = data.read()
        else:
            b = data
        self.objects[f"{bucket}/{object_name}"] = b[:length]

def test_minio_upload_and_sign():
    fake = FakeMinio()
    es = EvidenceStore(minio_client=fake)
    signer = EvidenceSigner()
    es.attach_signer(signer)
    data = b'minio-evidence'
    res = es.save_evidence(data, {'name':'mtest.bin','bucket':'evidence','object_name':'mtest.bin'})
    assert res['location'].startswith('minio://')
    assert 'signature' in res
