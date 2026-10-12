"""Remember which folders the user has allowed AppLedger to send to the hosted service.

Nothing is uploaded from a folder until the user has seen what would be sent and said yes,
once per folder. Consents live in ~/.appledger/consent.json, keyed by the folder's absolute path.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .scanner import APPLEDGER_HOME, ScanError

CONSENT_FILE = APPLEDGER_HOME / "consent.json"


class ConsentRequired(ScanError):
    """A hosted check needs the user's go-ahead first. plan is the upload plan to show them."""

    def __init__(self, message, plan):
        super().__init__(message)
        self.plan = plan


def interactive():
    """True if a person can answer a question typed on stdin.

    On Windows the NUL device (stdin of scheduled tasks and many tools) also claims to be a
    terminal, so ask the console itself.
    """
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
        if os.name != "nt":
            return True
        import ctypes
        import msvcrt
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(ctypes.c_ulong())))
    except (AttributeError, OSError, ValueError):
        return False


def folder_key(app_dir):
    return str(Path(app_dir).resolve())


def load():
    try:
        data = json.loads(CONSENT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def has_consent(app_dir):
    key = os.path.normcase(folder_key(app_dir))
    return any(os.path.normcase(k) == key for k in load())


def give_consent(app_dir, file_count):
    data = {k: v for k, v in load().items() if os.path.normcase(k) != os.path.normcase(folder_key(app_dir))}
    data[folder_key(app_dir)] = {"given_at": datetime.now().isoformat(timespec="seconds"), "files": file_count}
    CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONSENT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return CONSENT_FILE
