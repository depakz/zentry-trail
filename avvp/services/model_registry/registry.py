import os
import json
import joblib
from typing import Any, Dict, Optional

class ModelRegistry:
    def __init__(self, path: str = None):
        self.path = path or os.path.join(os.path.dirname(__file__), '..', '..', 'models')
        os.makedirs(self.path, exist_ok=True)
        self.index_file = os.path.join(self.path, 'index.json')
        if not os.path.exists(self.index_file):
            with open(self.index_file, 'w') as f:
                json.dump({}, f)

    def save(self, model_path: str, name: str, metadata: Optional[Dict] = None) -> str:
        # copy the model file into registry and register metadata
        import shutil
        target = os.path.join(self.path, os.path.basename(model_path))
        # avoid copying if source and target are the same file
        try:
            if os.path.abspath(model_path) != os.path.abspath(target):
                shutil.copyfile(model_path, target)
        except shutil.SameFileError:
            pass
        with open(self.index_file, 'r') as f:
            idx = json.load(f)
        entry = {'path': target, 'metadata': metadata or {}, 'name': name}
        idx[name] = entry
        with open(self.index_file, 'w') as f:
            json.dump(idx, f, indent=2)
        return target

    def get(self, name: str) -> Dict:
        with open(self.index_file, 'r') as f:
            idx = json.load(f)
        return idx.get(name)

    def load(self, name: str) -> Any:
        entry = self.get(name)
        if not entry:
            return None
        return joblib.load(entry['path'])
