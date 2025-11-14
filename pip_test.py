"""
This script is for CI/CD and manual verification that the dpqc package is installed from PyPI,
not from the local source. It will fail if the import is from a local directory.
"""
import sys
import os
import importlib.util

# Check sys.path for local source directory
local_dir = os.path.abspath(os.path.dirname(__file__))
if local_dir in sys.path:
    sys.path.remove(local_dir)

# Try to import dpqc and check version
try:
    import dpqc
    print(f"dpqc version: {dpqc.__version__}")
    assert dpqc.__version__ == "0.0.1", f"Expected version 0.0.1, got {dpqc.__version__}"
    # Check that dpqc is not loaded from local source
    dpqc_path = dpqc.__file__
    if local_dir in dpqc_path:
        raise AssertionError(f"dpqc is loaded from local source: {dpqc_path}")
    print(f"dpqc is loaded from: {dpqc_path}")
    # Try importing all classes
    from dpqc import MLKEM512, MLKEM768, MLKEM1024, MLDSA44, MLDSA65, MLDSA87, Falcon512, Falcon1024
    print("All classes imported successfully from pip-installed dpqc.")
except Exception as e:
    print(f"[pip_test] FAILED: {e}")
    sys.exit(1)
print("[pip_test] PASSED: dpqc is installed from pip and version is correct.")
