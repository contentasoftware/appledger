# AppLedger honest check (plugin)

Honest security checks, in plain language, for apps you build with AI in Claude Code or Codex.

Ask your agent "Is my app safe to share?" and AppLedger checks your project with independent scanners: Trivy for leaked keys, outdated libraries and risky container setup, and Opengrep for dangerous code patterns such as SQL injection or command injection. Your agent then explains each problem in everyday words, offers to fix it, and checks again so you can see the score improve.

Nothing to install besides the plugin: the scanners run on the AppLedger service.

## Data handling

**When you run a check, your project's source files are uploaded to the AppLedger scanning service** at `appledger.net` over HTTPS. Dependencies, build output, media and files over 1 MB are left out. The upload is scanned and deleted right after; we keep no copy of your code. We log only the time, a one-way hash of your IP address, the upload size, how long the check took and whether it succeeded.

Results are written to a `.appledger/` folder inside your project, which is excluded from version control.

Prefer to keep everything on your computer? Set `APPLEDGER_MODE=local` and install [Trivy](https://trivy.dev) and [Opengrep](https://github.com/opengrep/opengrep/releases) yourself.

## Requirements

- Python 3.10+ and [uv](https://docs.astral.sh/uv/) (the plugin starts its local MCP server with `uvx`)

## What's included

- `check-my-app` skill: runs the check, explains it, fixes problems with your permission and checks again
- `appledger` MCP server with four tools: `check_app`, `get_fix_prompt`, `ai_cost` (AI tokens and cost behind the app, read from your local Claude Code and Codex logs, never uploaded), `scanner_status`

More: https://appledger.net/
