from avvp.services.attack_graph.main import AttackGraphService


class FakeRecorder:
    def __init__(self):
        self.runs = []

    def run(self, *args, **kwargs):
        self.runs.append((args, kwargs))


class FakeSession:
    def __init__(self, recorder):
        self.recorder = recorder

    def __enter__(self):
        return self.recorder

    def __exit__(self, exc_type, exc, tb):
        return False

    def write_transaction(self, fn, *args, **kwargs):
        # Call the tx function with our recorder as tx
        fn(self.recorder, *args, **kwargs)


class FakeDriver:
    def __init__(self):
        self.recorder = FakeRecorder()

    def session(self):
        return FakeSession(self.recorder)

    def close(self):
        pass


def test_attack_graph_add_endpoint():
    svc = AttackGraphService()
    svc.driver = FakeDriver()
    svc.add_endpoint('scan1', {'url': 'http://example.com', 'method': 'GET', 'status_code': 200, 'params': ['id']})
    # ensure that a run was recorded
    assert len(svc.driver.recorder.runs) >= 1
