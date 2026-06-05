import importlib.util
import importlib.machinery
import importlib
import os
import sys

_here = os.path.dirname(__file__)
_src = os.path.join(_here, '..', 'event-schemas', 'schemas.py')
_mod_name = 'avvp.libs.event_schemas.schemas'
spec = importlib.util.spec_from_file_location(_mod_name, _src)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)
sys.modules[_mod_name] = _mod

# Re-export public names
for _name in getattr(_mod, '__all__', [n for n in dir(_mod) if not n.startswith('_')]):
    globals()[_name] = getattr(_mod, _name)

# also expose submodule attribute
schemas = _mod
