import importlib.util
import os
import sys

_here = os.path.dirname(__file__)
_src = os.path.join(_here, '..', 'mcts-planner', 'mcts.py')
_mod_name = 'avvp.services.mcts_planner.mcts'
spec = importlib.util.spec_from_file_location(_mod_name, _src)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)
sys.modules[_mod_name] = _mod

for _name in getattr(_mod, '__all__', [n for n in dir(_mod) if not n.startswith('_')]):
    globals()[_name] = getattr(_mod, _name)

mcts = _mod
