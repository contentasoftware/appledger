"""Send a project to the hosted AppLedger scanning service and get the findings back.

Only files that belong to the project are sent: in a git repository, the files git tracks or
would commit; elsewhere, the files the folder's .gitignore files don't exclude. Secrets files
(.env, keys, certificates, local tool settings), dependencies, build output, media and files
over 1 MB never leave the computer. upload_plan shows exactly what would be sent and why the
rest isn't. The upload goes over HTTPS, is scanned with Trivy and Opengrep, and is deleted on
the server right after.

In local mode nothing is uploaded; with a connection key, record_check sends only a summary
(name, score, problem counts, the problems' levels and titles) to the dashboard. Never the code
or file paths.

A hosted check without a connection key sends the app's name too, and gets back a save link: the
service keeps the check's summary (name, score, the problems' levels and titles) for 24 hours so
the user can save it to a free account, then deletes it. With save_to_dashboard=False
(--no-dashboard) the name isn't sent and no link is made.
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
from .gitfiles import project_listing
from .scanner import APPLEDGER_HOME, SKIP_DIRS, ScanError
from .uploadpolicy import holds_public_key_only, is_caution_only, is_encrypted_vault, is_secret_path

API_URL = os.environ.get("APPLEDGER_API", "https://appledger.net/api/check.php")
DEFAULT_RECORD_API = "https://appledger.net/api/record.php"
DASHBOARD_URL = "https://appledger.net/app/"
KEY_FILE = APPLEDGER_HOME / "key"
MAX_FILE_BYTES = 1_000_000
MAX_ZIP_BYTES = 10_000_000
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".mp4", ".mov", ".mp3", ".wav", ".pdf",
    ".zip", ".gz", ".tgz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar",
    ".pyc", ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".otf", ".psd", ".xlsx", ".docx",
}
# Documents and data files: the scanners don't need them, and they often hold business or personal data.
DATA_SUFFIXES = {
    ".csv", ".tsv", ".xls", ".xlsm", ".ods", ".doc", ".odt", ".rtf", ".ppt", ".pptx", ".odp", ".pages",
    ".numbers", ".parquet", ".avro", ".orc", ".feather", ".log", ".dump", ".bak", ".sql.gz", ".ndjson",
    ".jsonl", ".har", ".pcap", ".eml", ".msg", ".mbox", ".vcf", ".ics", ".sql",
}
# Files that may be Ansible Vault-encrypted under an ordinary name; the first bytes tell.
VAULT_SUFFIXES = {".yml", ".yaml", ".txt", ".cfg", ".ini", ".conf", ".json", ""}
DATA_FOLDER_WORDS = ("data", "dump", "export", "fixture", "sample", "traffic")
MAX_DATA_JSON_BYTES = 100_000
MAX_RECORDED_ISSUES = 60
LEVEL_RANK = {"blocker": 0, "important": 1, "minor": 2}


def looks_like_data(rel, size):
    """JSON or XML that is data rather than configuration: big, or kept in a data-like folder."""
    name = rel.rsplit("/", 1)[-1].lower()
    if not name.endswith((".json", ".xml", ".txt")) or name in {"package.json", "package-lock.json", "composer.json",
                                                        "tsconfig.json", "pom.xml"}:
        return False
    folders = rel.lower().split("/")[:-1]
    return size > MAX_DATA_JSON_BYTES or any(w in f for f in folders for w in DATA_FOLDER_WORDS) \
        or any(w in name for w in ("raw", "dump", "export", "traffic"))


def is_secret_entry(rel):
    """is_secret_path for a file, or for a folder listed as "name/" (meaning anything inside it)."""
    return is_secret_path(rel.rstrip("/") + "/file" if rel.endswith("/") else rel)


def upload_plan(app_dir):
    """What a hosted check would send, what it leaves out and why. Reads file names, never contents.

    Returns {"files": [path], "bytes": int, "excluded": [{"path", "reason"}],
             "secret_files_not_ignored": [{"path", "tracked"}], "git": bool, "folder": str}.
    reason is "secret file", "ignored by git", "too large", "media/binary" or "document or data". Folders git ignores
    as a whole are listed once, as "name/". secret_files_not_ignored lists the secrets files git
    would commit (tracked, or untracked and not ignored); it is only filled inside a git work tree.
    """
    app_dir = Path(app_dir).resolve()
    if not app_dir.is_dir():
        raise ScanError(f"{app_dir} is not a folder.")
    listing = project_listing(app_dir, SKIP_DIRS)
    files, excluded, exposed, total = [], [], [], 0
    for rel in sorted(listing["candidates"]):
        if SKIP_DIRS.intersection(rel.split("/")[:-1]):
            continue  # dependencies and build output: never useful to the scanners
        path = app_dir / rel
        if path.is_symlink() or not path.is_file():
            continue  # links could point outside the project; missing files were deleted but not committed
        vault = path.suffix.lower() in VAULT_SUFFIXES and is_encrypted_vault(path)
        if vault or is_secret_path(rel):
            excluded.append({"path": rel, "reason": "secret file"})
            # Encrypted vaults, public keys and secret templates are kept out of the upload, but having
            # them in git isn't a leak, so only real secrets files become findings.
            if listing["git"] and not (vault or is_caution_only(rel) or holds_public_key_only(path)):
                exposed.append({"path": rel, "tracked": rel in listing["tracked"]})
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            excluded.append({"path": rel, "reason": "media/binary"})
            continue
        size = path.stat().st_size
        if path.suffix.lower() in DATA_SUFFIXES or rel.lower().endswith(".sql.gz") or looks_like_data(rel, size):
            excluded.append({"path": rel, "reason": "document or data"})
            continue
        if size > MAX_FILE_BYTES:
            excluded.append({"path": rel, "reason": "too large"})
            continue
        files.append(rel)
        total += size
    for rel in listing["ignored"]:
        if SKIP_DIRS.intersection(rel.rstrip("/").split("/")):
            continue
        excluded.append({"path": rel, "reason": "secret file" if is_secret_entry(rel) else "ignored by git"})
    excluded.sort(key=lambda e: (e["reason"] != "secret file", e["path"]))
    return {"files": files, "bytes": total, "excluded": excluded, "secret_files_not_ignored": exposed,
            "git": listing["git"], "folder": str(app_dir)}


def human_size(n):
    return f"{n} bytes" if n < 1000 else f"{n / 1000:.0f} KB" if n < 1_000_000 else f"{n / 1_000_000:.1f} MB"


def upload_preview(plan, examples=10):
    """A short summary of an upload plan, to show the user before anything is sent."""
    return {"files": len(plan["files"]), "bytes": plan["bytes"],
            "excluded_secret_files": [e["path"] for e in plan["excluded"] if e["reason"] == "secret file"],
            "examples": plan["files"][:examples]}


def build_zip(app_dir, plan=None):
    """Zip the files in the upload plan. Returns (zip bytes, number of files, files left out as too large)."""
    app_dir = Path(app_dir).resolve()
    plan = plan or upload_plan(app_dir)
    files = [rel for rel in plan["files"] if not is_secret_path(rel)]  # never, whatever list was passed in
    if not files:
        raise ScanError(f"No files to check in {app_dir}. See what was left out with --list-files.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            zf.write(app_dir / rel, rel)
    data = buf.getvalue()
    if len(data) > MAX_ZIP_BYTES:
        raise ScanError(f"The project is too big to send ({len(data) // 1_000_000} MB after compression, "
                        f"limit {MAX_ZIP_BYTES // 1_000_000} MB). Check a smaller folder, or use local mode.")
    return data, len(files), [e["path"] for e in plan["excluded"] if e["reason"] == "too large"]


def connection_key():
    """The key that links checks to an AppLedger dashboard: APPLEDGER_KEY, else the saved key file."""
    key = os.environ.get("APPLEDGER_KEY", "").strip()
    if not key and KEY_FILE.is_file():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    return key or None


def save_connection_key(key):
    """Store a connection key from https://appledger.net/app/ for future checks on this computer."""
    key = key.strip()
    if not key.startswith("al_") or len(key) < 23:
        raise ScanError("That doesn't look like an AppLedger connection key. Keys start with al_ and come from "
                        f"{DASHBOARD_URL}")
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_text(key + "\n", encoding="utf-8")
    try:
        KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return KEY_FILE


def forget_connection_key():
    KEY_FILE.unlink(missing_ok=True)


def clean_name(app_name, app_dir):
    return " ".join((app_name or Path(app_dir).name).split())


def multipart(boundary, fields, data):
    parts = [f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
             for name, value in fields.items() if value is not None]
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"project\"; filename=\"project.zip\"\r\n"
                  f"Content-Type: application/zip\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts)


def error_message(e):
    """The service's own explanation from an HTTP error, if it sent one."""
    try:
        return json.load(e).get("error", "")
    except (ValueError, AttributeError, OSError):
        return ""


def hosted_scan(app_dir, app_name=None, plan=None, save_to_dashboard=True, local_findings=None):
    """Returns (findings, scanner names, ledger, save link) from the AppLedger service.

    Sends only the files in upload_plan (pass plan to reuse one already shown to the user). With
    save_to_dashboard, the app's name and local_findings (found on this computer, such as committed
    secrets files) are sent too, as level and title only, so a saved score matches the local report:
    - with a connection key, the result is saved to the organisation's dashboard and ledger says where;
    - without one, the service returns a save link ({"url", "expires_in_hours"}) that saves the result
      to a free account; ledger is None.
    Without save_to_dashboard neither the key nor the name is sent, and ledger and save link are None.
    """
    data, count, skipped = build_zip(app_dir, plan)
    boundary = uuid.uuid4().hex
    key = connection_key() if save_to_dashboard else None
    fields = {"app_name": clean_name(app_name, app_dir)} if save_to_dashboard else {}
    if save_to_dashboard and local_findings:
        fields["local_findings"] = json.dumps([{"level": f["level"], "title": summary_title(f)} for f in local_findings][:20])
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
        "User-Agent": f"appledger/{__version__}",
    }
    if key:
        headers["X-AppLedger-Key"] = key
    if not API_URL.lower().startswith(("https://", "http://")):
        raise ScanError("APPLEDGER_API must start with https:// (or http:// for a local test server).")
    req = urllib.request.Request(API_URL, data=multipart(boundary, fields, data), method="POST",  # nosemgrep -- scheme checked above
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:  # nosemgrep -- https/http checked above
            result = json.load(resp)
    except urllib.error.HTTPError as e:
        raise ScanError(error_message(e) or f"The AppLedger service answered with an error ({e.code}). "
                                            "Try again later.")
    except (urllib.error.URLError, TimeoutError) as e:
        raise ScanError(f"Couldn't reach the AppLedger service ({getattr(e, 'reason', e)}). "
                        "Check your internet connection, or run in local mode.")
    if not result.get("ok"):
        raise ScanError(result.get("error", "The AppLedger service couldn't check this project."))
    link = save_link(result) if save_to_dashboard and not key else None
    return result["findings"], result["scanners"], result.get("ledger"), link


def save_link(result):
    """The save link in a hosted check's answer, as {"url", "expires_in_hours"}, or None.

    Only web links are accepted, so a report never gets a link of another kind.
    """
    claim = result.get("claim") if isinstance(result, dict) else None
    url = claim.get("url") if isinstance(claim, dict) else None
    if not isinstance(url, str) or not url.startswith(("https://", "http://")) or len(url) > 500 or any(
            c.isspace() for c in url):
        return None
    hours = claim.get("expires_in_hours")
    return {"url": url, "expires_in_hours": hours if isinstance(hours, int) and 0 < hours <= 168 else 24}


def summary_title(finding, limit=200):
    """A problem's title for the dashboard: one line, without the file path some titles name in brackets."""
    title = finding.get("title") or ""
    where = (finding.get("where") or "").split(":")[0]
    if where:
        title = title.replace(f" ({where})", "")
    return " ".join(title.split())[:limit]


def summary_issues(findings, limit=MAX_RECORDED_ISSUES):
    """The problems a dashboard summary lists, most serious first: level, title and topic only."""
    issues = []
    for f in sorted(findings, key=lambda f: LEVEL_RANK.get(f.get("level"), 9)):
        title = summary_title(f)
        if f.get("level") in LEVEL_RANK and title:
            topic = " ".join(str(f.get("topic") or "").split())[:120] or None
            issues.append({"level": f["level"], "title": title, "topic": topic})
    return issues[:limit]


def record_payload(summary, counts):
    """The summary a local check sends to the dashboard: no code, no file contents or paths.

    counts uses the plain level keys (blocker, important, minor). issues lists up to 60 problems
    (level, title, topic), most serious first.
    """
    return {
        "app_name": clean_name(summary["app"], summary["app"]),
        "score": summary["score"],
        "grade": summary["grade"],
        "scanners": list(summary["scanners"]),
        "counts": {lvl: int(counts.get(lvl, 0)) for lvl in ("blocker", "important", "minor")},
        "top_issues": [summary_title(f, 160) for f in summary["findings"] if f["level"] == "blocker"][:3],
        "issues": summary_issues(summary["findings"]),
        "client_version": __version__,
    }


def record_check(payload, key=None):
    """Save a local check's summary to the dashboard. Never raises: a failure is reported in the result.

    Returns the service's ledger ({"recorded": True, "app", "dashboard"}) or {"recorded": False, "error"}.
    """
    key = key or connection_key()
    if not key:
        return {"recorded": False, "error": "This computer isn't connected to an AppLedger dashboard."}
    url = os.environ.get("APPLEDGER_RECORD_API", DEFAULT_RECORD_API)
    if not url.lower().startswith(("https://", "http://")):
        return {"recorded": False, "error": "APPLEDGER_RECORD_API must start with https://."}
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": f"appledger/{__version__}", "X-AppLedger-Key": key,
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep -- https/http checked above
            result = json.load(resp)
    except urllib.error.HTTPError as e:
        return {"recorded": False, "error": error_message(e) or f"The dashboard answered with an error ({e.code})."}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return {"recorded": False, "error": f"Couldn't reach the dashboard ({getattr(e, 'reason', e)})."}
    if not isinstance(result, dict):
        result = {}
    ledger = result.get("ledger")
    if not result.get("ok") or not isinstance(ledger, dict):
        return {"recorded": False, "error": result.get("error") or "The dashboard didn't accept the result."}
    return ledger
