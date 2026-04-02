import sys
import os

# Ensure the project root is on sys.path so that `scanners` and `core` can be imported
# regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(__file__))
