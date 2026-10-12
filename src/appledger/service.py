"""Server side of the hosted check: unpack an uploaded project safely, scan it, print JSON.

    python3 -m appledger.service <project.zip>

Called by the web endpoint for each upload. The project is unpacked into a fresh temporary
folder that is deleted when the scan finishes, whatever the outcome.
"""

import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from . import __version__
from .scanner import ScanError, scan

MAX_ENTRIES = 5000
MAX_UNPACKED_BYTES = 100_000_000


def safe_extract(zip_path, dest):
    """Unpack a zip, refusing absolute paths, '..' segments, links and zip bombs."""
    with zipfile.ZipFile(zip_path) as zf:
        entries = zf.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ScanError(f"Too many files in the project (limit {MAX_ENTRIES}).")
        if sum(e.file_size for e in entries) > MAX_UNPACKED_BYTES:
            raise ScanError("The project is too big once unpacked.")
        for entry in entries:
            name = PurePosixPath(entry.filename)
            if name.is_absolute() or ".." in name.parts or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ScanError(f"Refused an unsafe path in the upload: {entry.filename}")
            if entry.is_dir():
                continue
            target = Path(dest, *name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(entry) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: appledger.service <project.zip>"}))
        sys.exit(2)
    workdir = Path(tempfile.mkdtemp(prefix="al-"))
    try:
        app_dir = workdir / "app"
        app_dir.mkdir()
        safe_extract(sys.argv[1], app_dir)
        findings, scanners = scan(app_dir)
        print(json.dumps({"ok": True, "version": __version__, "scanners": scanners, "findings": findings}))
    except (ScanError, zipfile.BadZipFile) as e:
        print(json.dumps({"ok": False, "error": str(e) or "The upload isn't a valid zip file."}))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
