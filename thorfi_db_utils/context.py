import os
import sys

if getattr(sys, "frozen", False):
    executable = sys.executable
else:
    executable = __file__

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(executable), '..')))

import thorfi
