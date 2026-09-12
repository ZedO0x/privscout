import os
import sys

# Ensure the project root is importable (e.g. `from modules import system`)
# regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
