import importlib.util
import importlib
import os
import sys

_here = os.path.dirname(__file__)
_src = os.path.join(_here, '..', 'sarif-schema', 'sarif_builder.py')
_mod_name = 'avvp.libs.sarif_schema.sarif_builder'
spec = importlib.util.spec_from_file_location(_mod_name, _src)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)
sys.modules[_mod_name] = _mod

for _name in getattr(_mod, '__all__', [n for n in dir(_mod) if not n.startswith('_')]):
    globals()[_name] = getattr(_mod, _name)

# expose submodule
sarif_builder = _mod
