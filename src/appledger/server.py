"""MCP server for the AppLedger honest check.

Runs locally over stdio. By default check_app zips the project's files (only those git would
commit, never secrets files) and sends them to the hosted AppLedger scanning service, so no
scanners need to be installed. The first check of a folder needs the user's go-ahead: check_app
returns needs_confirmation with a preview until it's called with confirm_upload=True.
Set APPLEDGER_MODE=local to run Trivy and Opengrep on this machine instead, in which case no
code leaves the computer. Tools: check_app, preview_upload, get_fix_prompt, ai_cost,
connect_dashboard and scanner_status.
"""

import json
import os
import urllib.request
from pathlib import Path

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import __version__
from .client import (API_URL, DASHBOARD_URL, connection_key, human_size, save_connection_key, upload_plan,
                     upload_preview)
from .consent import ConsentRequired, has_consent
from .scanner import OUTPUT_DIR_NAME, ScanError, check, doctor

INSTALL_HINTS = {
    "trivy": "Install Trivy: https://trivy.dev (Windows: winget install AquaSecurity.Trivy, Mac: brew install trivy).",
    "opengrep": "Download Opengrep from https://github.com/opengrep/opengrep/releases and put it on PATH, "
                "or set APPLEDGER_OPENGREP to its path.",
    "opengrep_rules": "Run: git clone --depth 1 https://github.com/opengrep/opengrep-rules.git ~/.appledger/opengrep-rules",
}

mcp = FastMCP(
    "appledger",
    instructions=(
        "AppLedger checks apps that people built with AI for security problems, using independent "
        "scanners, and explains each problem in plain language. Use check_app on the app's folder. "
        "The first hosted check of a folder sends its files to appledger.net, so check_app first returns "
        "needs_confirmation with an upload_preview (how many files, which secrets files stay behind): show "
        "the user that preview, ask whether to send the files, and only if they say yes call check_app "
        "again with confirm_upload=true. Never set confirm_upload on your own. preview_upload lists every "
        "file at any time. Then explain the most serious problems first in everyday words, and offer to "
        "fix them using get_fix_prompt. After fixing, run check_app again and show the new score."
    ),
)


def hosted():
    return os.environ.get("APPLEDGER_MODE", "hosted") == "hosted"


@mcp.tool(annotations=ToolAnnotations(title="Check an app for security problems", readOnlyHint=False,
                                      destructiveHint=False, idempotentHint=True, openWorldHint=True))
async def check_app(path: str, app_name: str | None = None, confirm_upload: bool = False,
                    save_to_dashboard: bool = True) -> dict:
    """Scan an app folder with independent security scanners and explain the findings in plain language.

    Hosted mode sends the project's files over HTTPS to the AppLedger scanning service, where they are
    scanned with Trivy and Opengrep and deleted right after. Only files git would commit are sent; secrets
    files (.env, keys, certificates, local settings), dependencies, media and files over 1 MB never are.
    The first check of a folder returns needs_confirmation and an upload_preview instead of uploading:
    show the preview to the user and ask. Only after they agree, call again with confirm_upload=true;
    later checks of that folder don't ask again. Results are written to <path>/.appledger (report.html,
    fix-prompt.md, findings.json). Returns the score (0-100), grade, who may use the app right now, and
    every finding with why it matters and what to do.

    Args:
        path: absolute path to the app's folder.
        app_name: a friendly name for the app, shown in the report.
        confirm_upload: true only after the user agreed to send this folder's files to appledger.net.
        save_to_dashboard: false to keep this check out of the user's AppLedger dashboard.
    """
    try:
        result = await anyio.to_thread.run_sync(lambda: check(path, app_name=app_name, confirm_upload=confirm_upload,
                                                              save_to_dashboard=save_to_dashboard))
    except ConsentRequired as e:
        preview = upload_preview(e.plan)
        secrets = preview["excluded_secret_files"]
        return {
            "ok": False, "needs_confirmation": True, "upload_preview": preview,
            "message": (f"Nothing has been sent yet. Checking this app sends {preview['files']} files "
                        f"({human_size(preview['bytes'])}) to appledger.net, where they are scanned and deleted "
                        "right after. "
                        + (f"Secrets files stay on this computer: {', '.join(secrets[:5])}. " if secrets else "")
                        + "Ask the user whether to send them. If they agree, call check_app again with "
                          "confirm_upload=true. preview_upload lists every file; APPLEDGER_MODE=local checks "
                          "on this computer instead."),
        }
    except ScanError as e:
        return {"ok": False, "error": str(e), "help": "Run scanner_status to see what is wrong."}
    keep = ("level", "title", "why", "fix", "where")
    ledger = result.get("ledger")
    if not save_to_dashboard:
        dashboard = "Not saved to the dashboard, as asked."
    elif ledger:
        dashboard = ledger  # {"recorded": true, "app", "dashboard"}, or {"recorded": false, "error"}
    elif connection_key():
        dashboard = None
    else:
        dashboard = (f"Not connected. A free account at {DASHBOARD_URL} keeps every app, its owner and grade "
                     "in one ledger.")
    return {
        "ok": True,
        "app": result["app"], "score": result["score"], "grade": result["grade"],
        "scanners": result["scanners"], "counts": result["counts"],
        "who_can_use_it": result["who_can_use_it"],
        "findings": [{k: f[k] for k in keep} for f in result["findings"]],
        "report": result["report"], "fix_prompt": result["fix_prompt"],
        "checked_by": "AppLedger scanning service" if hosted() else "scanners on this computer",
        "ai_effort": short_usage(result.get("ai_usage")),
        "dashboard": dashboard,
    }


@mcp.tool(annotations=ToolAnnotations(title="Show which files a check would send", readOnlyHint=True, destructiveHint=False,
                                      openWorldHint=False))
def preview_upload(path: str) -> dict:
    """List the files a hosted check of this folder would send to appledger.net, and what stays behind.

    Nothing is sent. In a git repository only files git tracks or would commit count; elsewhere the
    folder's .gitignore files decide. Secrets files, media, files over 1 MB, dependencies and build output
    are always left out. Also lists secrets files git would commit, which the check reports as problems.

    Args:
        path: absolute path to the app's folder.
    """
    try:
        plan = upload_plan(path)
    except ScanError as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True, **upload_preview(plan, examples=50),
        "size": human_size(plan["bytes"]),
        "excluded": plan["excluded"][:100], "excluded_total": len(plan["excluded"]),
        "secret_files_not_ignored": plan["secret_files_not_ignored"],
        "selected_by": "git" if plan["git"] else ".gitignore files (not a git repository)",
        "mode": "hosted" if hosted() else "local (nothing is sent)",
        "upload_allowed": has_consent(path),
    }


def short_usage(usage):
    if not usage:
        return None
    return {"tokens": usage["tokens_total"], "sessions": usage["sessions"],
            "estimated_cost_usd": usage["cost_usd"], "note": usage["note"]}


@mcp.tool(annotations=ToolAnnotations(title="Estimate the AI tokens and cost behind an app", readOnlyHint=True, destructiveHint=False,
                                      openWorldHint=False))
def ai_cost(path: str) -> dict:
    """Estimate how many AI tokens went into building an app, and what they would cost at API list prices.

    Reads Claude Code and Codex session logs on this computer for sessions run in that folder; nothing is
    uploaded. Returns totals plus a breakdown per tool and model. People on flat-rate plans (Claude Pro,
    Max, Team) pay their plan price instead, so present the figure as the work's value at API rates.

    Args:
        path: absolute path to the app's folder.
    """
    from .scanner import ai_usage_for
    usage = ai_usage_for(Path(path).resolve())
    if not usage:
        return {"found": False, "message": "No Claude Code or Codex logs on this computer mention this folder."}
    return {"found": True, **usage}


@mcp.tool(annotations=ToolAnnotations(title="Get the fix request for an app", readOnlyHint=True, destructiveHint=False,
                                      openWorldHint=False))
def get_fix_prompt(path: str) -> str:
    """Return the fix request written by the last check_app run for this app folder.

    The fix request lists every problem in order, where it is, and the expected fix, plus rules such
    as never putting keys in code and never removing features to silence a warning.

    Args:
        path: absolute path to the app's folder (the same path given to check_app).
    """
    prompt = Path(path) / OUTPUT_DIR_NAME / "fix-prompt.md"
    if not prompt.exists():
        return "No check has been run for this folder yet. Run check_app first."
    return prompt.read_text(encoding="utf-8")


@mcp.tool(annotations=ToolAnnotations(title="Connect this computer to an AppLedger dashboard", readOnlyHint=False,
                                      destructiveHint=False, idempotentHint=True, openWorldHint=False))
def connect_dashboard(key: str) -> dict:
    """Save a connection key so future checks from this computer appear in the user's AppLedger dashboard.

    The user creates the key (it starts with al_) at https://appledger.net/app/ under "Connect a computer".
    The key is stored in ~/.appledger/key. Only call this with a key the user gave you.

    Args:
        key: the connection key, starting with al_.
    """
    try:
        where = save_connection_key(key)
    except ScanError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "saved_to": str(where), "dashboard": DASHBOARD_URL,
            "next": "Run check_app on an app; the result will appear in the dashboard."}


@mcp.tool(annotations=ToolAnnotations(title="Show AppLedger's status", readOnlyHint=True, destructiveHint=False, openWorldHint=True))
def scanner_status() -> dict:
    """Show whether the AppLedger scanning service is reachable (or, in local mode, which scanners are
    installed on this computer), and how to fix anything that is missing."""
    if hosted():
        try:
            with urllib.request.urlopen(API_URL, timeout=15) as resp:
                service = json.load(resp)
            return {"version": __version__, "mode": "hosted", "service": API_URL, "reachable": bool(service.get("ok")),
                    "dashboard_connected": bool(connection_key())}
        except Exception as e:  # report any network problem to the user instead of failing
            return {"version": __version__, "mode": "hosted", "service": API_URL, "reachable": False,
                    "how_to_fix": [f"Couldn't reach the service ({e}). Check the internet connection, or set "
                                   "APPLEDGER_MODE=local and install the scanners."]}
    found = doctor()
    return {
        "version": __version__, "mode": "local",
        "scanners": {tool: (where or "not found") for tool, where in found.items()},
        "how_to_fix": [INSTALL_HINTS[t] for t, where in found.items() if not where and t in INSTALL_HINTS],
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
