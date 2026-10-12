# AppLedger honest check

Honest security feedback, in plain language, for apps people build with AI tools such as Claude Code, Codex, Cursor and Lovable.

AppLedger checks your app folder with independent scanners and explains what they find in everyday words: what is wrong, why it matters, and what to do. It also writes a fix request you can hand straight to the AI tool that built the app, then checks again.

## What it checks

| Scanner | Finds |
|---|---|
| [Trivy](https://trivy.dev) | Leaked passwords and keys, outdated libraries with known security problems, risky container setup |
| [Opengrep](https://github.com/opengrep/opengrep) | Dangerous code patterns: SQL injection, command injection, unsafe data loading, debug mode left on |
| SonarQube (optional, local mode) | Code quality and more security hotspots, if you already run a SonarQube server |

Each run produces, in `<your-app>/.appledger/`:

- `report.html`: a score, who may use the app right now (only you, your team, the whole company), and every problem in plain words
- `fix-prompt.md`: a ready-made fix request for your coding agent
- `findings.json`: the same findings for tools and dashboards

## AI effort behind the app

Every check also reports how many AI tokens went into the app and what they would cost at API list prices. It reads the coding agents' own logs on your computer (Claude Code in `~/.claude/projects`, Codex in `~/.codex/sessions`), counts sessions that ran in the app's folder, and prices each reply by model, including cache reads and writes. These logs never leave your computer. On a flat-rate plan (Claude Pro, Max or Team) you pay your plan price instead, so the figure shows the work's value at API rates.

```
python -m appledger path/to/your-app --ai-cost
```

Codex support follows Codex's documented log format and hasn't been tested against real Codex logs yet.

## Two ways to run

| Mode | What you install | Where your code goes |
|---|---|---|
| **Hosted** (default) | Only this package | Source files are zipped, sent over HTTPS to the AppLedger service, scanned and deleted right after |
| **Local** (`--local` or `APPLEDGER_MODE=local`) | Also Trivy, Opengrep and the Opengrep rules | Nowhere: everything runs on your computer |

## Use it

```
pip install appledger
python -m appledger path/to/your-app
```

Add it to Claude Code as an MCP server:

```
claude mcp add appledger -- uvx --from appledger appledger-mcp
```

Then ask: "Is my app safe to share?" Or install the full plugin with the guided skill from `plugin/`.

## Local mode setup

1. Trivy: `winget install AquaSecurity.Trivy` (Windows) or `brew install trivy` (Mac)
2. Opengrep: download from the [releases page](https://github.com/opengrep/opengrep/releases) and put it on your PATH
3. Rules: `git clone --depth 1 https://github.com/opengrep/opengrep-rules.git ~/.appledger/opengrep-rules`
4. Check: `python -m appledger --doctor`

## Repository layout

| Path | What |
|---|---|
| `src/appledger/scanner.py` | Scanners, plain-language translation, report and fix request |
| `src/appledger/client.py` | Sends a project to the hosted service |
| `src/appledger/service.py` | Server side: unpacks an upload safely and scans it |
| `src/appledger/server.py` | Local MCP server used by the plugin |
| `plugin/` | Claude Code / Codex plugin with the `check-my-app` skill |
| `tests/mcp_smoke.py` | Calls every MCP tool like an agent would |

## License

MIT. The Opengrep community rules used by the scanner have their own license (Commons Clause); check it before using them in a paid service.
