"""Shared set-up for the plain-assert tests: run them with `python tests/test_<name>.py` (or pytest).

Importing this module points APPLEDGER_HOME at a fresh temporary folder, so tests never touch the
real ~/.appledger (consents, connection key), and puts src/ on the import path.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TMP = Path(tempfile.mkdtemp(prefix="appledger-test-"))
os.environ["APPLEDGER_HOME"] = str(TMP / "home")
os.environ.pop("APPLEDGER_KEY", None)
os.environ.pop("APPLEDGER_MODE", None)
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def write(path, text="x\n"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")  # exact bytes, also on Windows
    return path


def new_dir(name):
    path = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=TMP))
    return path


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def fake_response(data):
    """Something urlopen can return: a context manager json.load can read."""
    return io.BytesIO(json.dumps(data).encode("utf-8"))


def run_all(namespace):
    """Run every test_* function in a module; exit 1 if any failed."""
    failed = 0
    tests = [(name, fn) for name, fn in namespace.items() if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except Exception:  # report every failure, then keep going
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
    print(f"{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
