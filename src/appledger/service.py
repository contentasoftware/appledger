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
from .scanner import ScanError, grade_for, health_score, scan
from .uploadpolicy import is_secret_path

MAX_ENTRIES = 5000
MAX_UNPACKED_BYTES = 100_000_000


def safe_extract(zip_path, dest):
    """Unpack a zip, refusing absolute paths, '..' segments, links and zip bombs.

    Secret-bearing files (see uploadpolicy) are skipped without being read, in case a client
    sent one anyway. Returns how many were skipped; their names are never logged or returned.
    """
    skipped = 0
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
            if is_secret_path(name.as_posix()):
                skipped += 1
                continue
            target = Path(dest, *name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(entry) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return skipped


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: appledger.service <project.zip>"}))
        sys.exit(2)
    workdir = Path(tempfile.mkdtemp(prefix="al-"))
    try:
        app_dir = workdir / "app"
        app_dir.mkdir()
        skipped = safe_extract(sys.argv[1], app_dir)
        findings, scanners = scan(app_dir)
        score = health_score(findings)
        print(json.dumps({"ok": True, "version": __version__, "scanners": scanners, "findings": findings,
                          "score": score, "grade": grade_for(score), "skipped_secret_files": skipped}))
    except (ScanError, zipfile.BadZipFile) as e:
        print(json.dumps({"ok": False, "error": str(e) or "The upload isn't a valid zip file."}))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
