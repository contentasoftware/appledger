---
name: check-my-app
description: Check an app the user built with AI for security problems before they share it, explain the results in plain language, and fix them. Use when the user asks whether their app is safe, secure or ready to share, wants a security check or review, or is about to deploy or share an app with colleagues.
---

# Check my app

The user built an app, often with an AI tool, and wants to know if it's safe to share. They may not be a developer. Your job: get an honest, independent verdict, explain it in everyday words, and fix what they agree to fix.

## 1. Run the check

1. Find the app's folder. Use the current project unless the user names another folder. Pass an absolute path.
2. Before the first check, tell the user in one sentence: the project's source files are sent to the AppLedger scanning service over an encrypted connection, checked, and deleted right after. If they'd rather not, stop here.
3. Call the `check_app` tool from the AppLedger MCP server with that path. It usually takes 10–30 seconds; tell the user it's running.
4. If it returns `ok: false`, show the error in plain words. Call `scanner_status` if the service seems unreachable.

## 2. Explain the result

Lead with the verdict, then the problems. Keep it short and concrete.

- Start with the grade, the score, and who may use the app right now (from `who_can_use_it`).
- Explain the "Fix before sharing" items first, one line each, using the finding's own plain wording. Say what could happen, not the technical name.
- Summarize "Fix soon" items in a sentence or two. Mention "Good to know" items only if asked.
- Don't paste CVE numbers, rule IDs or file dumps unless the user asks.
- Tell them the full report is in `report.html` (give the path) if they want to read it.

Then ask: "Do you want me to fix these?"

## 3. Fix, then check again

1. Call `get_fix_prompt` with the same path and follow it, most serious first.
2. After each fix, say in one plain sentence what you changed.
3. Never remove a feature to make a warning disappear. If a fix would change how the app behaves, ask first.
4. Never put keys or passwords in code. Move them to environment variables. **Tell the user that any key that was in the code must be treated as leaked and replaced** (for example a new Stripe or Slack key), because you can't do that for them.
5. When done, call `check_app` again and show the old and new score side by side, plus anything still open.

## AI effort

`check_app` also returns `ai_effort`: how many AI tokens went into the app, measured from Claude Code and Codex logs on this computer, and what they would cost at API list prices. If present, mention it in one line after the verdict. If the user asks how much AI or money went into the app, call `ai_cost` for the breakdown. Always add that on a flat-rate plan (Claude Pro, Max or Team) they pay their plan price, not this amount.

## Tone

Be honest and calm. Don't scare, don't reassure falsely. If the scanners found nothing serious, say so plainly, and add that scanners can't catch everything (for example a page with no login that shows private data), so the user should still think about who can reach each page.
