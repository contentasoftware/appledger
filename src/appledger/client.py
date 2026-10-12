"""Send a project to the hosted AppLedger scanning service and get the findings back.

The project is zipped (without dependencies, build output, media or other large files),
sent over HTTPS, scanned with Trivy and Opengrep, and deleted on the server right after.
"""

import io
import json
import os
import uuid
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import __version__
from .scanner import ScanError, app_files

API_URL = os.environ.get("APPLEDGER_API", "https://www.contenta-software.com/appledger/api/check.php")
MAX_FILE_BYTES = 1_000_000
MAX_ZIP_BYTES = 10_000_000
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".mp4", ".mov", ".mp3", ".wav", ".pdf",
    ".zip", ".gz", ".tgz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar",
    ".pyc", ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".otf", ".psd", ".xlsx", ".docx",
}


def build_zip(app_dir):
    """Zip the files the scanners need. Returns (zip bytes, number of files, skipped files)."""
    app_dir = Path(app_dir)
    buf = io.BytesIO()
    count, skipped = 0, []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(app_files(app_dir)):
            rel = path.relative_to(app_dir).as_posix()
            if path.suffix.lower() in SKIP_SUFFIXES or path.is_symlink():
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(rel)
                continue
            zf.write(path, rel)
            count += 1
    data = buf.getvalue()
    if count == 0:
        raise ScanError(f"No files to check in {app_dir}.")
    if len(data) > MAX_ZIP_BYTES:
        raise ScanError(f"The project is too big to send ({len(data) // 1_000_000} MB after compression, "
                        f"limit {MAX_ZIP_BYTES // 1_000_000} MB). Check a smaller folder, or use local mode.")
    return data, count, skipped


def hosted_scan(app_dir):
    """Returns (findings, scanner names) from the AppLedger service."""
    data, count, skipped = build_zip(app_dir)
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"project\"; filename=\"project.zip\"\r\n"
            f"Content-Type: application/zip\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
        "User-Agent": f"appledger/{__version__}",
    })
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            message = json.load(e).get("error", "")
        except (ValueError, AttributeError):
            message = ""
        raise ScanError(message or f"The AppLedger service answered with an error ({e.code}). Try again later.")
    except (urllib.error.URLError, TimeoutError) as e:
        raise ScanError(f"Couldn't reach the AppLedger service ({getattr(e, 'reason', e)}). "
                        "Check your internet connection, or run in local mode.")
    if not result.get("ok"):
        raise ScanError(result.get("error", "The AppLedger service couldn't check this project."))
    return result["findings"], result["scanners"]
