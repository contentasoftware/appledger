"""Estimate how many AI tokens, and what they would cost, went into building a project.

Reads the coding agents' own logs on this computer, so the numbers are measured, not guessed:

    Claude Code   ~/.claude/projects/<folder>/*.jsonl   (CLAUDE_CONFIG_DIR overrides ~/.claude)
    Codex         ~/.codex/sessions/**/*.jsonl          (CODEX_HOME overrides ~/.codex)

Costs use Anthropic's API list prices. People on a flat-rate plan (Claude Pro/Max/Team) pay
their plan price instead, so the figure shows the work's value at API rates, not their bill.
Nothing here is sent anywhere.
"""

import json
import os
import re
from collections import defaultdict
from pathlib import Path

PRICES_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing (checked 2026-10-12)"

# USD per million tokens: input, 5-minute cache write, 1-hour cache write, cache read, output.
CLAUDE_PRICES = {
    "claude-fable-5-1": (10, 12.5, 20, 0.25, 50),
    "claude-mythos-5-1": (10, 12.5, 20, 0.25, 50),
    "claude-fable-5": (10, 12.5, 20, 1, 50),
    "claude-mythos-5": (10, 12.5, 20, 1, 50),
    "claude-opus-5-5": (4, 5, 8, 0.20, 20),
    "claude-opus-5": (5, 6.25, 10, 0.50, 25),
    "claude-opus-4-8": (5, 6.25, 10, 0.50, 25),
    "claude-opus-4-7": (5, 6.25, 10, 0.50, 25),
    "claude-opus-4-6": (5, 6.25, 10, 0.50, 25),
    "claude-opus-4-5": (5, 6.25, 10, 0.50, 25),
    "claude-opus-4-1": (15, 18.75, 30, 1.50, 75),
    "claude-opus-4": (15, 18.75, 30, 1.50, 75),
    "claude-sonnet-5-5": (2, 2.5, 4, 0.10, 10),
    "claude-sonnet-5": (2, 2.5, 4, 0.20, 10),
    "claude-sonnet-4-6": (3, 3.75, 6, 0.30, 15),
    "claude-sonnet-4-5": (3, 3.75, 6, 0.30, 15),
    "claude-sonnet-4": (3, 3.75, 6, 0.30, 15),
    "claude-haiku-5-5": (0.10, 0.125, 0.20, 0.01, 0.50),
    "claude-haiku-4-5": (1, 1.25, 2, 0.10, 5),
    "claude-3-5-haiku": (0.80, 1, 1.60, 0.08, 4),
}
HAIKU_5_5_LONG = (0.50, 0.625, 1, 0.05, 2.50)  # prompts over 100,000 tokens
FAST_MODE_FACTOR = 2.0   # fast mode on Opus 5.5 / 5 / 4.8 is billed at 2x the standard rates
US_ONLY_FACTOR = 1.1     # inference_geo "us" on Claude 4.6 and later


def claude_home():
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))


def codex_home():
    return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))


def price_key(model):
    """Map a logged model name (dated, prefixed or regional) to a price table key."""
    name = (model or "").lower().split("/")[-1]
    name = re.sub(r"^(?:[a-z]{2,4}\.)?anthropic\.", "", name)          # Bedrock prefixes
    name = re.sub(r"-v\d+(?::\d+)?$", "", name)                       # Bedrock "-v1:0"
    name = re.sub(r"[-@]\d{8}$", "", name)                              # snapshot dates
    for key in sorted(CLAUDE_PRICES, key=len, reverse=True):
        if name == key or name.startswith(key + "-") or name.startswith(key + "@"):
            return key
    return None


def message_cost(model, usage):
    key = price_key(model)
    if not key:
        return None
    cache_5m, cache_1h = cache_writes(usage)
    inp, cread, out = usage.get("input_tokens", 0), usage.get("cache_read_input_tokens", 0), usage.get("output_tokens", 0)
    rates = CLAUDE_PRICES[key]
    if key == "claude-haiku-5-5" and inp + cread + cache_5m + cache_1h > 100_000:
        rates = HAIKU_5_5_LONG
    cost = (inp * rates[0] + cache_5m * rates[1] + cache_1h * rates[2] + cread * rates[3] + out * rates[4]) / 1e6
    if usage.get("speed") == "fast":
        cost *= FAST_MODE_FACTOR
    if usage.get("inference_geo") == "us":
        cost *= US_ONLY_FACTOR
    return cost


def cache_writes(usage):
    detail = usage.get("cache_creation") or {}
    if detail:
        return detail.get("ephemeral_5m_input_tokens", 0), detail.get("ephemeral_1h_input_tokens", 0)
    return usage.get("cache_creation_input_tokens", 0), 0


def same_or_inside(child, parent):
    child, parent = os.path.normcase(os.path.abspath(child)), os.path.normcase(os.path.abspath(parent))
    return child == parent or child.startswith(parent.rstrip("\\/") + os.sep)


def claude_code_usage(app_dir):
    """Token use from Claude Code sessions run inside app_dir (and, separately, in its parent folders)."""
    root = claude_home() / "projects"
    if not root.is_dir():
        return None
    encoded = re.sub(r"[^A-Za-z0-9]", "-", os.path.abspath(app_dir))
    candidates = [d for d in root.iterdir() if d.is_dir() and (
        d.name.lower().startswith(encoded.lower()) or encoded.lower().startswith(d.name.lower() + "-"))]
    messages = {}  # message id -> (model, usage, cwd, session, timestamp); streaming repeats each message
    for folder in candidates:
        for log in folder.rglob("*.jsonl"):
            with open(log, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if '"usage"' not in line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    msg = entry.get("message")
                    if entry.get("type") != "assistant" or not isinstance(msg, dict) or not msg.get("usage"):
                        continue
                    key = msg.get("id") or f"{log.name}:{entry.get('uuid')}"
                    previous = messages.get(key)
                    if previous and previous[1].get("output_tokens", 0) >= msg["usage"].get("output_tokens", 0):
                        continue
                    messages[key] = (msg.get("model"), msg["usage"], entry.get("cwd") or "",
                                     entry.get("sessionId") or log.stem, entry.get("timestamp") or "")
    inside, parent = new_totals(), new_totals()
    for model, usage, cwd, session, ts in messages.values():
        if model == "<synthetic>":
            continue
        bucket = inside if cwd and same_or_inside(cwd, app_dir) else parent if cwd and same_or_inside(app_dir, cwd) else None
        if bucket is not None:
            add(bucket, model, usage, session, ts)
    return {"tool": "Claude Code", "this_folder": finish(inside), "parent_folders": finish(parent)}


def codex_usage(app_dir):
    """Token use from Codex sessions run inside app_dir. Codex logs running totals per session."""
    root = codex_home() / "sessions"
    if not root.is_dir():
        return None
    totals = new_totals()
    for log in root.rglob("*.jsonl"):
        cwd, model, last, ts = "", "", None, ""
        with open(log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                payload = entry.get("payload") or {}
                if entry.get("type") in ("session_meta", "turn_context"):
                    cwd = payload.get("cwd") or cwd
                    model = payload.get("model") or model
                elif entry.get("type") == "event_msg" and payload.get("type") == "token_count":
                    last = (payload.get("info") or {}).get("total_token_usage") or last
                ts = entry.get("timestamp") or ts
        if cwd and last and same_or_inside(cwd, app_dir):
            usage = {"input_tokens": last.get("input_tokens", 0) - last.get("cached_input_tokens", 0),
                     "cache_read_input_tokens": last.get("cached_input_tokens", 0),
                     "output_tokens": last.get("output_tokens", 0)}
            add(totals, model or "unknown", usage, log.stem, ts)
    return {"tool": "Codex", "this_folder": finish(totals), "parent_folders": None}


def new_totals():
    return {"by_model": defaultdict(lambda: defaultdict(float)), "sessions": set(), "first": "", "last": ""}


def add(totals, model, usage, session, ts):
    m = totals["by_model"][model]
    cache_5m, cache_1h = cache_writes(usage)
    m["input"] += usage.get("input_tokens", 0)
    m["cache_write"] += cache_5m + cache_1h
    m["cache_read"] += usage.get("cache_read_input_tokens", 0)
    m["output"] += usage.get("output_tokens", 0)
    m["messages"] += 1
    cost = message_cost(model, usage)
    if cost is None:
        m["unpriced"] += 1
    else:
        m["cost_usd"] += cost
    totals["sessions"].add(session)
    if ts:
        totals["first"] = min(totals["first"] or ts, ts)
        totals["last"] = max(totals["last"], ts)


def finish(totals):
    if not totals["by_model"]:
        return None
    by_model = {model: {k: round(v, 4) if k == "cost_usd" else int(v) for k, v in vals.items()}
                for model, vals in totals["by_model"].items()}
    tokens = sum(v["input"] + v["cache_write"] + v["cache_read"] + v["output"] for v in by_model.values())
    return {
        "sessions": len(totals["sessions"]), "first": totals["first"][:10], "last": totals["last"][:10],
        "tokens_total": tokens,
        "output_tokens": sum(v["output"] for v in by_model.values()),
        "cost_usd": round(sum(v.get("cost_usd", 0) for v in by_model.values()), 2),
        "unpriced_messages": sum(v.get("unpriced", 0) for v in by_model.values()),
        "by_model": by_model,
    }


def estimate_usage(app_dir):
    """Combine every agent log found for app_dir. Returns None when no logs mention this folder."""
    found = [r for r in (claude_code_usage(app_dir), codex_usage(app_dir))
             if r and (r["this_folder"] or r.get("parent_folders"))]
    if not found:
        return None
    here = [r["this_folder"] for r in found if r["this_folder"]]
    return {
        "tools": found,
        "tokens_total": sum(h["tokens_total"] for h in here),
        "cost_usd": round(sum(h["cost_usd"] for h in here), 2),
        "sessions": sum(h["sessions"] for h in here),
        "prices": PRICES_SOURCE,
        "note": ("Measured from the coding agents' logs on this computer and priced at API list prices. "
                 "On a flat-rate plan (Claude Pro, Max or Team) you pay your plan price instead."),
    }
