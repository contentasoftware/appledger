# AppLedger honest check

<!-- mcp-name: net.appledger/appledger -->

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
| **Hosted** (default) | Only this package | Source files Git would commit are zipped, sent over HTTPS to `appledger.net`, scanned and deleted right after. Secret files are never sent. You confirm before the first upload of each folder |
| **Local** (`--local` or `APPLEDGER_MODE=local`) | Also Trivy, Opengrep and the Opengrep rules | Stays on your computer. With a connection key, only a summary goes to your dashboard (see below); `--no-dashboard` skips even that |

## What gets uploaded in hosted mode

- **Sent:** files Git would commit (`git ls-files`, including new files that aren't ignored). Outside a Git repository, `.gitignore` is still honoured.
- **Never sent:** `.env` and `.env.*` (except `.env.example`, `.env.sample`, `.env.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, SSH keys, `.npmrc`, `.pypirc`, `.netrc`, `*credentials*.json`, `service-account*.json`, `secrets.*`, the folders `cert`, `certs`, `secrets`, `.ssh` and `.aws`, `.claude/settings.local.json`, Terraform state, password files, Ansible Vault files, Kubernetes/Helm secret manifests, certificates and similar (full list in `src/appledger/uploadpolicy.py`). The server drops such files again as a second safety net.
- **Skipped:** dependencies, build output, media, documents and data files (CSV, spreadsheets, slides, SQL, logs, data dumps) and files over 1 MB.

If a secret file is committed to Git or not ignored, the check reports it as a problem by file name. Its content is never read or sent.

See exactly what would be sent, and what is left out and why, without uploading anything:

```
python -m appledger path/to/your-app --list-files
```

The first hosted check of a folder asks you to confirm. In scripts and scheduled runs, pass `--yes`. If the code belongs to your employer or a client, make sure you're allowed to upload it, or use local mode.

## Install

**Claude Code plugin** (recommended: adds the guided `check-my-app` skill):

```
claude plugin marketplace add contentasoftware/appledger
claude plugin install appledger@appledger
```

In the Claude Code desktop app, add the marketplace `contentasoftware/appledger` in the plugin settings instead. Start a new session, then ask: "Is my app safe to share?" or "Add this app to AppLedger".

**MCP server only** (needs [uv](https://docs.astral.sh/uv/)):

```
claude mcp add appledger -- uvx --from appledger appledger-mcp
```

**Command line:**

```
pip install appledger
python -m appledger path/to/your-app
```

Step-by-step guide with troubleshooting: https://appledger.net/docs/

Version 0.2.0 (upload preview, consent, secret-file exclusion, scheduling) is being released to PyPI; until then `pip install appledger` gets 0.1.x.

## Company dashboard

Create a free account at [appledger.net](https://appledger.net/app/signup.php) to keep every app your people check in one ledger: owner, grade, score trend, who may use it and the AI cost behind it. Create a connection key under "Connect a computer", then save it on each computer:

```
python -m appledger --connect al_your_key
```

Or tell Claude: "Connect AppLedger with this key: al_…". The key is saved in `~/.appledger/key`; `APPLEDGER_KEY` overrides it and `--disconnect` removes it.

From then on each check also saves a summary to your dashboard: the app's name, score, grade, problem counts, up to 3 titles of the most serious problems, the scanners used and the AI cost totals. Never the code.

You can also add an app in the web app with **Add app**: register it without code, or upload a zip to check it in the browser (the zip is scanned and deleted the same way).

## Scheduled checks

```
python -m appledger path/to/your-app --schedule weekly --yes   # or daily
python -m appledger --schedules                                 # list
python -m appledger path/to/your-app --schedule off             # stop
```

Uses Windows Task Scheduler on Windows and cron on macOS and Linux. Hosted scheduled checks need the one-time `--yes` consent; add `--local` to schedule local checks instead. `--quiet` prints one line per check.

## Local mode setup

1. Trivy: `winget install AquaSecurity.Trivy` (Windows) or `brew install trivy` (Mac)
2. Opengrep: download from the [releases page](https://github.com/opengrep/opengrep/releases) and put it on your PATH
3. Rules: `git clone --depth 1 https://github.com/opengrep/opengrep-rules.git ~/.appledger/opengrep-rules`
4. Check: `python -m appledger --doctor`

## Repository layout

| Path | What |
|---|---|
| `src/appledger/scanner.py` | Scanners, plain-language translation, report and fix request |
| `src/appledger/client.py` | Picks the files to send (honouring `.gitignore`) and sends them to the hosted service |
| `src/appledger/uploadpolicy.py` | The full list of secret files that are never uploaded, used by client and server |
| `src/appledger/service.py` | Server side: unpacks an upload safely and scans it |
| `src/appledger/server.py` | Local MCP server used by the plugin |
| `plugin/` | Claude Code / Codex plugin with the `check-my-app` skill |
| `tests/mcp_smoke.py` | Calls every MCP tool like an agent would |

## License

MIT. The Opengrep community rules used by the scanner have their own license (Commons Clause); check it before using them in a paid service.
