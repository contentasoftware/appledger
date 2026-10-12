"""Which files in a project folder belong to the project, the way git sees it.

Inside a git work tree, git itself answers: tracked files plus untracked files it doesn't
ignore. Outside one, the folder's .gitignore files are read here (comments, negation with !,
trailing / for folders, *, ** and patterns anchored with /), so a project that was never
committed gets the same treatment. Only file names are looked at, never contents.
"""

import os
import re
import subprocess
from pathlib import Path

# Git on Windows and macOS matches ignore patterns without regard to case by default.
IGNORE_CASE = os.path.normcase("A") == "a"


def run_git(app_dir, *args):
    """(exit code, stdout bytes) of a git command run in app_dir, or (None, b"") if git can't run."""
    try:
        proc = subprocess.run(["git", "-C", str(app_dir), *args], capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None, b""
    return proc.returncode, proc.stdout


def zsplit(out):
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def in_git_work_tree(app_dir):
    """True if git can say which files of app_dir belong to the project."""
    code, out = run_git(app_dir, "rev-parse", "--is-inside-work-tree")
    if code != 0 or out.strip() != b"true":
        return False
    # A folder its own repository ignores (say, a scratch app under an ignored folder) gets
    # nothing from git ls-files, so it's treated like a folder outside git instead.
    code, _ = run_git(app_dir, "check-ignore", "-q", ".")
    return code == 1


def collapse(entries):
    """Drop entries that sit inside a folder already listed (git lists both in some cases)."""
    out, dirs = [], []
    for entry in sorted(dict.fromkeys(entries)):
        if any(entry.startswith(d) for d in dirs):
            continue
        out.append(entry)
        if entry.endswith("/"):
            dirs.append(entry)
    return out


def git_listing(app_dir):
    """Ask git. Paths are relative to app_dir, even when app_dir is a subfolder of the repository."""
    _, cached = run_git(app_dir, "ls-files", "--cached", "-z")
    _, others = run_git(app_dir, "ls-files", "--others", "--exclude-standard", "-z")
    _, ignored = run_git(app_dir, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    tracked = zsplit(cached)
    return {
        "git": True,
        "candidates": list(dict.fromkeys(tracked + zsplit(others))),
        "tracked": set(tracked),
        "ignored": collapse(zsplit(ignored)),
    }


# ---- .gitignore files, for folders outside git ----

def translate(pattern):
    """Turn one gitignore glob into a regular expression matched against a whole path."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("/.*")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[" and "]" in pattern[i + 2:]:  # a set like [abc] or [!abc]; ']' first is literal
            end = pattern.index("]", i + 2)
            body = pattern[i + 1:end]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end
        elif c == "\\" and i + 1 < len(pattern):
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE if IGNORE_CASE else 0)


def parse_rule(line, base):
    """One .gitignore line -> rule dict, or None for blanks and comments."""
    line = line.rstrip("\r\n")
    if not line.endswith("\\ "):
        line = line.rstrip(" ")
    if not line or line.startswith("#"):
        return None
    negate = line.startswith("!")
    if negate:
        line = line[1:]
    elif line[:2] in ("\\#", "\\!"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    # A slash at the start or in the middle ties the pattern to this .gitignore's folder;
    # without one it matches a name at any depth below it.
    anchored = "/" in line
    line = line.lstrip("/")
    if not line:
        return None
    try:
        regex = translate(line)
    except (re.error, ValueError):
        return None
    return {"base": base, "regex": regex, "negate": negate, "dir_only": dir_only, "anchored": anchored}


def read_rules(gitignore, base):
    try:
        text = gitignore.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [r for r in (parse_rule(line, base) for line in text.splitlines()) if r]


def is_ignored(rules, rel, is_dir):
    """Last matching rule wins, with deeper .gitignore files read after shallower ones."""
    ignored = False
    for r in rules:
        if r["dir_only"] and not is_dir:
            continue
        sub = rel[len(r["base"]) + 1:] if r["base"] else rel
        target = sub if r["anchored"] else sub.rsplit("/", 1)[-1]
        if r["regex"].match(target):
            ignored = not r["negate"]
    return ignored


def gitignore_listing(app_dir, skip_dirs=()):
    """Walk app_dir honouring its .gitignore files. Ignored folders are listed once, as "name/"."""
    app_dir = Path(app_dir)
    candidates, ignored = [], []

    def walk(dir_rel, rules):
        folder = app_dir / dir_rel if dir_rel else app_dir
        rules = rules + read_rules(folder / ".gitignore", dir_rel)
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            rel = f"{dir_rel}/{entry.name}" if dir_rel else entry.name
            is_dir = entry.is_dir(follow_symlinks=False)
            if is_dir and (entry.name == ".git" or entry.name in skip_dirs):
                continue
            if is_ignored(rules, rel, is_dir):
                # Like git: nothing inside an ignored folder can be brought back by a later rule.
                ignored.append(rel + "/" if is_dir else rel)
            elif is_dir:
                walk(rel, rules)
            else:
                candidates.append(rel)

    walk("", [])
    return {"git": False, "candidates": candidates, "tracked": set(), "ignored": ignored}


def project_listing(app_dir, skip_dirs=()):
    """Files git would consider part of the project, plus what it ignores, relative to app_dir.

    Returns {"git": bool, "candidates": [path], "tracked": {path}, "ignored": [path or "folder/"]}.
    """
    app_dir = Path(app_dir).resolve()
    if in_git_work_tree(app_dir):
        return git_listing(app_dir)
    return gitignore_listing(app_dir, skip_dirs)
