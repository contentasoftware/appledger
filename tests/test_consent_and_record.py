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
from unittest import mock

import anyio

from helpers import SRC, git, new_dir, run_all, write, fake_response

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

    def do_POST(self):
        FakeService.bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps({"ok": True, "findings": [FAKE_FINDING], "scanners": ["Trivy", "Opengrep"]}).encode()
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
            mock.patch("urllib.request.urlopen", return_value=answer) as urlopen, \
            mock.patch.object(scanner, "ai_usage_for", return_value=None):
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
    with mock.patch.object(scanner, "scan", return_value=([dict(FAKE_FINDING)], ["Trivy", "Opengrep"])), \
            mock.patch.object(scanner, "ai_usage_for", return_value=None):
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
    assert set(body) == {"app_name", "score", "grade", "scanners", "counts", "top_issues", "ai_tool", "ai_tokens",
                         "ai_cost_usd", "client_version"}, body
    assert body["counts"] == {"blocker": 2, "important": 0, "minor": 0}
    assert body["top_issues"] == ["Your code contains a Slack key", "Your repository contains a secrets file (.env)"]
    assert body["grade"] in "ABCDF" and isinstance(body["score"], int) and body["client_version"] == "0.2.0"
    assert body["ai_tool"] is None and body["ai_tokens"] is None and body["ai_cost_usd"] is None


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
            mock.patch("urllib.request.urlopen", return_value=answer) as urlopen, \
            mock.patch.object(scanner, "ai_usage_for", return_value=None):
        scanner.check(app, mode="hosted", confirm_upload=True, save_to_dashboard=False)
    req = urlopen.call_args[0][0]
    assert req.get_header("X-appledger-key") is None and b'name="app_name"' not in req.data


if __name__ == "__main__":
    run_all(dict(globals()))
