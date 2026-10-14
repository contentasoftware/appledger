"""Consent before the first upload (CLI and MCP), and what local mode sends to the dashboard.

Nothing here talks to appledger.net: the CLI tests use a throwaway HTTP server on 127.0.0.1,
the in-process tests replace urlopen.
"""

import io
import json
import os
import subprocess
import sys
import threading
import urllib.error
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import anyio

from helpers import SRC, git, new_dir, run_all, write, fake_response

import appledger
from appledger import scanner
from appledger.consent import CONSENT_FILE, has_consent

FAKE_FINDING = {"source": "Trivy", "kind": "secret", "level": "blocker", "title": "Your code contains a Slack key",
                "why": "w", "fix": "f", "where": "app.py:3", "technical": "t"}


def make_app():
    app = new_dir("app")
    git(app, "init", "-q")
    write(app / "app.py", "print('hi')\n")
    write(app / ".env", "API_KEY=never-read\n")
    git(app, "add", "app.py", ".env")
    return app


class FakeService(BaseHTTPRequestHandler):
    bodies = []
    extra = {}  # added to every answer, such as a save link

    def do_POST(self):
        FakeService.bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps({"ok": True, "findings": [FAKE_FINDING], "scanners": ["Trivy", "Opengrep"],
                           **FakeService.extra}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def cli(app, *args, api="http://127.0.0.1:9/none"):
    env = {**os.environ, "PYTHONPATH": str(SRC), "APPLEDGER_API": api}
    return subprocess.run([sys.executable, "-m", "appledger", str(app), *args], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, env=env, encoding="utf-8")


def test_cli_without_consent_refuses_when_not_interactive():
    app = make_app()
    FakeService.bodies.clear()
    server = HTTPServer(("127.0.0.1", 0), FakeService)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        proc = cli(app, api=f"http://127.0.0.1:{server.server_port}/api/check.php")
    finally:
        server.shutdown()
    assert proc.returncode != 0
    assert "hasn't been allowed to send" in proc.stderr and "--yes" in proc.stderr, proc.stderr
    assert FakeService.bodies == []  # nothing was uploaded
    assert not has_consent(app)


def test_cli_hosted_schedule_needs_consent():
    app = make_app()
    proc = cli(app, "--schedule", "daily")
    assert proc.returncode != 0 and "Not scheduled" in proc.stderr, proc.stderr
    assert not has_consent(app)


def test_cli_list_files_shows_plan_without_uploading():
    app = make_app()
    proc = cli(app, "--list-files")
    assert proc.returncode == 0, proc.stderr
    assert "sends these 1 files" in proc.stdout and "app.py" in proc.stdout
    assert ".env" in proc.stdout and "secret file" in proc.stdout and "tracked by git" in proc.stdout
    assert not has_consent(app)


def test_cli_yes_gives_consent_and_never_sends_secrets():
    app = make_app()
    FakeService.bodies.clear()
    server = HTTPServer(("127.0.0.1", 0), FakeService)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        proc = cli(app, "--yes", "--quiet", api=f"http://127.0.0.1:{server.server_port}/api/check.php")
    finally:
        server.shutdown()
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.strip().splitlines()) == 1, proc.stdout  # --quiet: one summary line
    assert "2 fix before sharing" in proc.stdout  # the service's finding plus the tracked .env
    body = FakeService.bodies[0]
    assert b"never-read" not in body and b"X-AppLedger-Key" not in body
    zipped = body[body.index(b"PK\x03\x04"):body.rindex(b"\r\n--")]
    assert zipfile.ZipFile(io.BytesIO(zipped)).namelist() == ["app.py"]
    assert has_consent(app)
    saved = json.loads(CONSENT_FILE.read_text(encoding="utf-8"))
    entry = next(v for k, v in saved.items() if os.path.normcase(k) == os.path.normcase(str(app.resolve())))
    assert entry["files"] == 1 and entry["given_at"]
    report = json.loads((app / ".appledger" / "findings.json").read_text(encoding="utf-8"))
    assert any(f["title"] == "Your repository contains a secrets file (.env)" for f in report["findings"])


def test_cli_prompt_in_a_terminal():
    import appledger.consent
    app = make_app()
    argv = ["appledger", str(app), "--quiet"]
    # Saying no sends nothing.
    with mock.patch.object(sys, "argv", argv), mock.patch.object(appledger.consent, "interactive", return_value=True), \
            mock.patch("builtins.input", return_value="n") as asked, \
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("must not upload")):
        try:
            scanner.main()
            raise AssertionError("expected exit")
        except SystemExit as e:
            assert "Nothing was sent" in str(e.code)
    assert asked.call_args[0][0] == "Send these 1 files to appledger.net for checking? [y/N] "
    assert not has_consent(app)
    # Saying yes uploads and remembers.
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"]})
    with mock.patch.object(sys, "argv", argv), mock.patch.object(appledger.consent, "interactive", return_value=True), \
            mock.patch("builtins.input", return_value="y"), \
            mock.patch("urllib.request.urlopen", return_value=answer) as urlopen:
        scanner.main()
    assert urlopen.call_count == 1 and has_consent(app)


def test_mcp_check_app_asks_first():
    from appledger import server
    app = make_app()
    with mock.patch("urllib.request.urlopen", side_effect=AssertionError("must not upload")):
        result = anyio.run(server.check_app, str(app))
    assert result["ok"] is False and result["needs_confirmation"] is True
    preview = result["upload_preview"]
    assert preview == {"files": 1, "bytes": len("print('hi')\n"), "excluded_secret_files": [".env"],
                       "examples": ["app.py"]}, preview
    assert "confirm_upload=true" in result["message"]
    assert not has_consent(app)

    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"]})
    with mock.patch("urllib.request.urlopen", return_value=answer) as urlopen:
        result = anyio.run(lambda: server.check_app(str(app), confirm_upload=True))
    assert result["ok"] is True, result
    assert urlopen.call_count == 1 and has_consent(app)
    assert result["findings"][0]["title"] == "Your repository contains a secrets file (.env)"

    preview = server.preview_upload(str(app))
    assert preview["ok"] and preview["files"] == 1 and preview["upload_allowed"] is True
    assert preview["secret_files_not_ignored"] == [{"path": ".env", "tracked": True}]


def local_check(app, save=True):
    with mock.patch.object(scanner, "scan", return_value=([dict(FAKE_FINDING)], ["Trivy", "Opengrep"])):
        return scanner.check(app, mode="local", save_to_dashboard=save)


def test_local_mode_records_summary_to_dashboard():
    app = make_app()
    ledger = {"recorded": True, "app": "x", "dashboard": "https://appledger.net/app/?app=x"}
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30,
                                      "APPLEDGER_RECORD_API": "http://127.0.0.1:9/record.php"}), \
            mock.patch("urllib.request.urlopen", return_value=fake_response({"ok": True, "ledger": ledger})) as urlopen:
        result = local_check(app)
    assert result["ledger"] == ledger
    req = urlopen.call_args[0][0]
    assert req.full_url == "http://127.0.0.1:9/record.php" and req.get_method() == "POST"
    assert req.get_header("X-appledger-key") == "al_" + "k" * 30
    assert req.get_header("Content-type") == "application/json"
    body = json.loads(req.data)
    assert set(body) == {"app_name", "score", "grade", "scanners", "counts", "top_issues", "issues",
                         "client_version"}, body
    assert body["counts"] == {"blocker": 2, "important": 0, "minor": 0}
    # Titles only: the secrets file's path is left out, and so are where, why, fix and technical details.
    assert body["top_issues"] == ["Your code contains a Slack key", "Your repository contains a secrets file"]
    assert body["issues"] == [
        {"level": "blocker", "title": "Your code contains a Slack key", "topic": None},
        {"level": "blocker", "title": "Your repository contains a secrets file", "topic": "secrets file tracked by git"},
    ], body["issues"]
    assert ".env" not in req.data.decode() and "app.py" not in req.data.decode()
    assert body["grade"] in "ABCDF" and isinstance(body["score"], int) and body["client_version"] == appledger.__version__
    # A check never reads coding agents' logs, and never reports AI tools, token counts or costs.
    assert not any(k.startswith("ai_") for k in body) and "ai_usage" not in result
    report = Path(result["report"]).read_text(encoding="utf-8")
    assert "$" not in report and "token" not in report.lower(), "the report must not show AI cost"


def test_record_payload_issues_most_serious_first_and_capped():
    from appledger.client import record_payload
    findings = [{"source": "Trivy", "kind": "outdated", "level": "minor", "title": f"pkg{n} is out of date",
                 "where": "requirements.txt"} for n in range(70)]
    findings.append({"source": "Opengrep", "kind": "security", "level": "important", "title": "Debug mode\nis on",
                     "where": "src/app.py:9", "technical": "rule", "topic": "Debug mode is on"})
    findings.append({"source": "AppLedger", "kind": "secret", "level": "important",
                     "title": "A secrets file isn't ignored by git (config/prod.env)", "where": "config/prod.env",
                     "topic": "secrets file not ignored by git"})
    body = record_payload({"app": "x", "score": 40, "grade": "D", "scanners": ["Trivy"], "findings": findings},
                          {"important": 2, "minor": 70})
    issues = body["issues"]
    assert len(issues) == 60 and all(set(i) == {"level", "title", "topic"} for i in issues)
    assert [i["level"] for i in issues[:3]] == ["important", "important", "minor"]
    assert issues[0] == {"level": "important", "title": "Debug mode is on", "topic": "Debug mode is on"}
    assert issues[1]["title"] == "A secrets file isn't ignored by git"
    assert "prod.env" not in json.dumps(body) and "src/app.py" not in json.dumps(body)
    assert len(json.dumps(body).encode()) < 65_536  # the record API's size limit
    assert body["top_issues"] == []


def test_hosted_local_findings_leave_out_file_paths():
    app = make_app()
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"]})
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30}), \
            mock.patch("urllib.request.urlopen", return_value=answer) as urlopen:
        scanner.check(app, mode="hosted", confirm_upload=True)
    data = urlopen.call_args[0][0].data
    sent = data[data.index(b'name="local_findings"'):data.index(b"PK\x03\x04")]
    assert b'name="ai_' not in data, "hosted checks send no AI tool, token or cost fields"
    assert b'"title": "Your repository contains a secrets file"' in sent and b".env" not in sent, sent


def test_local_mode_record_failure_does_not_fail_the_check():
    app = make_app()
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30}), \
            mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
        result = local_check(app)
    assert result["ledger"]["recorded"] is False and "offline" in result["ledger"]["error"]
    assert result["score"] < 100


def test_no_dashboard_skips_recording_and_key():
    app = make_app()
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30}), \
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("must not record")):
        assert local_check(app, save=False)["ledger"] is None
    # Hosted: the upload still happens, but without the key.
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"]})
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30}), \
            mock.patch("urllib.request.urlopen", return_value=answer) as urlopen:
        scanner.check(app, mode="hosted", confirm_upload=True, save_to_dashboard=False)
    req = urlopen.call_args[0][0]
    assert req.get_header("X-appledger-key") is None and b'name="app_name"' not in req.data


CLAIM_URL = "https://appledger.net/app/claim.php?t=" + "T" * 43
CLAIM = {"claim": {"url": CLAIM_URL, "expires_in_hours": 24}}


def serve_with(extra):
    FakeService.bodies.clear()
    FakeService.extra = extra
    server = HTTPServer(("127.0.0.1", 0), FakeService)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/api/check.php"


def test_cli_prints_save_link_and_report_shows_it():
    app = make_app()
    server, api = serve_with(CLAIM)
    try:
        proc = cli(app, "--yes", "--app-name", "Team  wiki", api=api)
    finally:
        server.shutdown()
        FakeService.extra = {}
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.strip().splitlines()
    assert lines[-1] == f"Save this result to a free AppLedger ledger (link works for 24 hours): {CLAIM_URL}", lines
    assert lines[1].startswith("Report: "), lines
    body = FakeService.bodies[0]
    # An anonymous check asks for a save link by sending the app's name (and the local problems' levels
    # and titles, so the saved score matches the report), never the key, a secret or a file path.
    assert b'name="app_name"\r\n\r\nTeam wiki\r\n' in body, body[:400]
    sent = body[:body.index(b"PK\x03\x04")]
    assert b'"title": "Your repository contains a secrets file"' in sent and b".env" not in sent and b"never-read" not in body
    out = app / ".appledger"
    report = (out / "report.html").read_text(encoding="utf-8")
    assert "Keep this result" in report and f'href="{CLAIM_URL}"' in report and "24 hours" in report
    saved = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert saved["save_link"] == {"url": CLAIM_URL, "expires_in_hours": 24}


def test_cli_quiet_prints_one_line_without_link():
    app = make_app()
    server, api = serve_with(CLAIM)
    try:
        proc = cli(app, "--yes", "--quiet", api=api)
    finally:
        server.shutdown()
        FakeService.extra = {}
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.strip().splitlines()) == 1 and "claim.php" not in proc.stdout, proc.stdout


def test_no_dashboard_asks_for_no_save_link():
    app = make_app()
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"], **CLAIM})
    with mock.patch("urllib.request.urlopen", return_value=answer) as urlopen:
        result = scanner.check(app, mode="hosted", confirm_upload=True, save_to_dashboard=False)
    data = urlopen.call_args[0][0].data
    assert b'name="app_name"' not in data and b'name="local_findings"' not in data
    assert result["save_link"] is None
    assert "Keep this result" not in Path(result["report"]).read_text(encoding="utf-8")


def test_connected_check_gets_no_save_link():
    app = make_app()
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"], **CLAIM,
                            "ledger": {"recorded": True, "app": "x", "dashboard": "https://appledger.net/app/"}})
    with mock.patch.dict(os.environ, {"APPLEDGER_KEY": "al_" + "k" * 30}),             mock.patch("urllib.request.urlopen", return_value=answer):
        result = scanner.check(app, mode="hosted", confirm_upload=True)
    assert result["save_link"] is None and result["ledger"]["recorded"] is True


def test_save_link_only_accepts_web_links():
    from appledger.client import save_link
    assert save_link({"claim": {"url": "javascript:alert(1)", "expires_in_hours": 24}}) is None
    assert save_link({"claim": {"url": "https://x.test/a b"}}) is None
    assert save_link({"claim": "https://x.test/"}) is None and save_link({}) is None
    assert save_link({"claim": {"url": CLAIM_URL, "expires_in_hours": "soon"}}) == {"url": CLAIM_URL,
                                                                                   "expires_in_hours": 24}


def test_mcp_check_app_returns_save_link():
    from appledger import server
    app = make_app()
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"], **CLAIM})
    with mock.patch("urllib.request.urlopen", return_value=answer):
        result = anyio.run(lambda: server.check_app(str(app), confirm_upload=True))
    assert result["ok"] is True and result["save_link"] == CLAIM_URL, result
    assert "save_link" in result["dashboard"] and "24 hours" in result["dashboard"]
    assert "save_link" in server.mcp.instructions and "once" in server.mcp.instructions
    # Without a link in the answer, there is no save_link key at all.
    answer = fake_response({"ok": True, "findings": [], "scanners": ["Trivy"]})
    with mock.patch("urllib.request.urlopen", return_value=answer):
        result = anyio.run(lambda: server.check_app(str(app), confirm_upload=True))
    assert "save_link" not in result and "Not connected" in result["dashboard"]


if __name__ == "__main__":
    run_all(dict(globals()))
