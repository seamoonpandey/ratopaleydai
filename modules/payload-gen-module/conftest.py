import sys
import os

# ensure this module directory is at front of sys.path
_dir = os.path.dirname(__file__)
if _dir in sys.path:
    sys.path.remove(_dir)
sys.path.insert(0, _dir)

# clear cached app module so it reimports from this directory
for mod_name in list(sys.modules):
    if mod_name == "app" or mod_name.startswith("app."):
        del sys.modules[mod_name]
