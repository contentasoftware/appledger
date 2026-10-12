# AppLedger honest check (plugin)

Security checks, in plain English, for apps you build with AI in Claude Code or Codex.

Ask your agent "Is my app safe to share?" or "Add this app to AppLedger". AppLedger checks your project with independent scanners: Trivy for leaked keys, outdated libraries and risky container setup, and Opengrep for dangerous code patterns such as SQL injection or command injection. Your agent explains each problem in everyday words, offers to fix it, and checks again so you can see the score improve.

Full guide: https://appledger.net/docs/


## Try it

- "Is my app safe to share?"
- "Add this app to AppLedger."
- "How much did it cost to build this app with AI?"

## Install

Terminal:

```
claude plugin marketplace add contentasoftware/appledger
claude plugin install appledger@appledger
```

Claude Code desktop app: open the plugin settings, add the marketplace `contentasoftware/appledger`, then install **appledger**.

Then start a new session so the plugin loads.

## What leaves your computer

By default (hosted mode) **your project's source files are uploaded to the AppLedger scanning service** at `appledger.net` over HTTPS, scanned, and deleted right after. We keep no copy of your code.

- **Sent:** only files Git would commit (tracked files plus new files that aren't ignored; `.gitignore` is honoured even outside Git).
- **Never sent:** secret files such as `.env` and `.env.*` (except `.env.example`, `.sample`, `.template`), `*.pem`, `*.key`, `*.p12`/`*.pfx`, SSH keys, `.npmrc`, `.pypirc`, `.netrc`, `*credentials*.json`, `service-account*.json`, `secrets.*`, the folders `cert`, `certs`, `secrets`, `.ssh` and `.aws`, `.claude/settings.local.json`, Terraform state, password files (`*.passwd`), Ansible Vault files, Kubernetes/Helm secret manifests and certificates. The server drops such files again as a second safety net. If a real secrets file is committed to Git or not ignored, the check reports it by file name. Its content is never sent; AppLedger only reads the first bytes on your computer to tell encrypted vaults and public keys (which are not leaks) from private ones.
- **Skipped:** dependencies, build output, media, documents and data files (CSV, spreadsheets, slides, SQL, logs, data dumps) and files over 1 MB.
- **Logged:** only the time, a one-way hash of your IP address, the upload size, how long the check took and whether it succeeded.

**You confirm first.** Before the first upload of a folder, your agent shows what would be sent (`preview_upload`) and asks you. If the code belongs to your employer or a client, make sure you're allowed to upload it, or use local mode.

**Local mode** keeps the code on your computer: set `APPLEDGER_MODE=local` and install [Trivy](https://trivy.dev) and [Opengrep](https://github.com/opengrep/opengrep/releases). If the computer is connected to a dashboard, only a summary is saved there (app name, score, grade, problem counts, up to 3 top problem titles, scanners used, AI cost totals). Ask for "don't save to the dashboard" to skip even that.

Results are written to a `.appledger/` folder inside your project, which is excluded from version control.

## Requirements

- Python 3.10+ and [uv](https://docs.astral.sh/uv/) (the plugin starts its MCP server on your computer with `uvx`)

## What's included

- `check-my-app` skill: asks before uploading, runs the check, explains it, fixes problems with your permission and checks again
- `appledger` MCP server with these tools: `preview_upload` (what would be sent, without sending), `check_app`, `get_fix_prompt`, `ai_cost` (AI tokens and cost behind the app, read from your Claude Code and Codex logs on this computer, never uploaded), `connect_dashboard`, `scanner_status`

More: https://appledger.net/
