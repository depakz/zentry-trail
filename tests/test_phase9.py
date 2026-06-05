import os
from avvp.services.gnn_trainer.trainer import GNNTrainer
from avvp.services.model_registry.registry import ModelRegistry


def test_gnn_trainer_and_registry(tmp_path):
    findings = [
        {'message': 'admin login page shows error', 'vuln_class': 'auth'},
        {'message': 'sql error on search', 'vuln_class': 'sqli'},
        {'message': 'admin login fail', 'vuln_class': 'auth'},
    ]
    trainer = GNNTrainer(out_dir=str(tmp_path))
    model = trainer.train_from_findings(findings)
    assert 'centroids' in model
    path = trainer.persist_model(model, 'phase9-test')
    assert os.path.exists(path)

    reg = ModelRegistry(path=str(tmp_path))
    saved = reg.save(path, 'phase9-test', {'notes': 'unit test'})
    assert os.path.exists(saved)
    loaded = reg.load('phase9-test')
    assert 'centroids' in loaded
