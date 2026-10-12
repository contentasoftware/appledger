"""MCP server for the AppLedger honest check.

Runs locally over stdio. By default check_app zips the project and sends it to the hosted
AppLedger scanning service, so no scanners need to be installed. Set APPLEDGER_MODE=local to run
Trivy and Opengrep on this machine instead, in which case nothing leaves the computer.
Exposes three tools: check_app, get_fix_prompt and scanner_status.
"""

import json
import os
import urllib.request
from pathlib import Path

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import __version__
from .client import API_URL
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
        "scanners, and explains each problem in plain language. Use check_app on the app's folder, "
        "explain the most serious problems first in everyday words, then offer to fix them using "
        "get_fix_prompt. After fixing, run check_app again and show the new score."
    ),
)


def hosted():
    return os.environ.get("APPLEDGER_MODE", "hosted") == "hosted"


@mcp.tool(annotations=ToolAnnotations(title="Check an app for security problems", readOnlyHint=False,
                                      destructiveHint=False, idempotentHint=True, openWorldHint=True))
async def check_app(path: str, app_name: str | None = None) -> dict:
    """Scan an app folder with independent security scanners and explain the findings in plain language.

    The project's source files (not dependencies, media or files over 1 MB) are zipped and sent over
    HTTPS to the AppLedger scanning service, scanned with Trivy and Opengrep, and deleted right after;
    nothing is stored. Tell the user this before the first check. Results are written to
    <path>/.appledger (report.html, fix-prompt.md, findings.json). Returns the score (0-100), grade,
    who may use the app right now, and every finding with why it matters and what to do.

    Args:
        path: absolute path to the app's folder.
        app_name: a friendly name for the app, shown in the report.
    """
    try:
        result = await anyio.to_thread.run_sync(lambda: check(path, app_name=app_name))
    except ScanError as e:
        return {"ok": False, "error": str(e), "help": "Run scanner_status to see what is wrong."}
    keep = ("level", "title", "why", "fix", "where")
    return {
        "ok": True,
        "app": result["app"], "score": result["score"], "grade": result["grade"],
        "scanners": result["scanners"], "counts": result["counts"],
        "who_can_use_it": result["who_can_use_it"],
        "findings": [{k: f[k] for k in keep} for f in result["findings"]],
        "report": result["report"], "fix_prompt": result["fix_prompt"],
        "checked_by": "AppLedger scanning service" if hosted() else "scanners on this computer",
        "ai_effort": short_usage(result.get("ai_usage")),
    }


def short_usage(usage):
    if not usage:
        return None
    return {"tokens": usage["tokens_total"], "sessions": usage["sessions"],
            "estimated_cost_usd": usage["cost_usd"], "note": usage["note"]}


@mcp.tool(annotations=ToolAnnotations(title="Estimate the AI tokens and cost behind an app", readOnlyHint=True,
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


@mcp.tool(annotations=ToolAnnotations(title="Get the fix request for an app", readOnlyHint=True,
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


@mcp.tool(annotations=ToolAnnotations(title="Show AppLedger's status", readOnlyHint=True, openWorldHint=True))
def scanner_status() -> dict:
    """Show whether the AppLedger scanning service is reachable (or, in local mode, which scanners are
    installed on this computer), and how to fix anything that is missing."""
    if hosted():
        try:
            with urllib.request.urlopen(API_URL, timeout=15) as resp:
                service = json.load(resp)
            return {"version": __version__, "mode": "hosted", "service": API_URL, "reachable": bool(service.get("ok"))}
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
