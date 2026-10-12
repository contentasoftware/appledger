"""Which files a hosted check sends: git's view, .gitignore files outside git, and secrets files."""

import zipfile
import io

from helpers import git, new_dir, run_all, write

from appledger.client import build_zip, upload_plan
from appledger.gitfiles import gitignore_listing
from appledger.scanner import findings_for_secret_files


def reasons(plan):
    return {e["path"]: e["reason"] for e in plan["excluded"]}


def make_repo():
    """A git repo with the app in a subfolder, like a monorepo."""
    repo = new_dir("repo")
    git(repo, "init", "-q")
    write(repo / ".gitignore", "*.log\nsecrets.env\napp/ignored_dir/\n")
    app = repo / "app"
    write(app / "main.py", "print('hi')\n")
    write(app / ".env", "API_KEY=never-read\n")                  # tracked secret -> blocker
    write(app / "run_cypress_lab.env", "TOKEN=never-read\n")     # untracked, not ignored -> important
    write(app / "secrets.env", "X=1\n")                         # ignored by git -> neither
    write(app / "notes.txt")                                     # untracked, not ignored -> sent
    write(app / "debug.log")                                     # ignored by git
    write(app / "ignored_dir" / "a.py")                          # whole folder ignored
    write(app / "cert" / "server.crt", "-----BEGIN CERT-----\n")  # secret folder
    write(app / ".claude" / "settings.local.json", "{}\n")
    write(app / "logo.png")
    write(app / "node_modules" / "lib" / "index.js")             # dependencies: never sent, not listed
    write(app / "big.js", "x" * 1_100_000)
    write(repo / "outside.py")                                   # outside the app folder
    git(repo, "add", ".gitignore", "app/main.py", "app/.env")
    return repo, app


def test_git_selection_in_subfolder():
    repo, app = make_repo()
    plan = upload_plan(app)
    assert plan["git"] is True
    assert sorted(plan["files"]) == ["main.py", "notes.txt"], plan["files"]
    why = reasons(plan)
    assert why[".env"] == "secret file"
    assert why["run_cypress_lab.env"] == "secret file"
    assert why["cert/server.crt"] == "secret file"
    assert why[".claude/settings.local.json"] == "secret file"
    assert why["secrets.env"] == "secret file"  # ignored by git, but a secret whatever git says
    assert why["debug.log"] == "ignored by git"
    assert why["ignored_dir/"] == "ignored by git"
    assert why["logo.png"] == "media/binary"
    assert why["big.js"] == "too large"
    assert not any("node_modules" in p for p in why) and "outside.py" not in why
    assert plan["bytes"] == len("print('hi')\n") + len("x\n")


def test_secret_files_git_would_commit():
    repo, app = make_repo()
    exposed = {e["path"]: e["tracked"] for e in upload_plan(app)["secret_files_not_ignored"]}
    assert exposed[".env"] is True
    assert exposed["run_cypress_lab.env"] is False
    assert "secrets.env" not in exposed  # git ignores it: fine
    findings = {f["where"]: f for f in findings_for_secret_files(upload_plan(app)["secret_files_not_ignored"])}
    assert findings[".env"]["level"] == "blocker"
    assert findings[".env"]["title"] == "Your repository contains a secrets file (.env)"
    assert findings["run_cypress_lab.env"]["level"] == "important"
    assert findings["run_cypress_lab.env"]["title"] == "A secrets file isn't ignored by git (run_cypress_lab.env)"
    for f in findings.values():
        assert {"source", "kind", "level", "title", "why", "fix", "where", "technical", "topic"} <= set(f)
        assert "never-read" not in str(f)


def test_zip_never_contains_secrets():
    repo, app = make_repo()
    data, count, too_large = build_zip(app)
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert sorted(names) == ["main.py", "notes.txt"], names
    assert count == 2 and too_large == ["big.js"]
    # Even a hand-made plan can't smuggle a secrets file in.
    data, count, _ = build_zip(app, {"files": ["main.py", ".env"], "excluded": []})
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["main.py"]


def test_folder_ignored_by_its_repo_uses_gitignore_files():
    repo = new_dir("repo")
    git(repo, "init", "-q")
    write(repo / ".gitignore", "scratch/\n")
    app = repo / "scratch" / "app"
    write(app / "app.py")
    write(app / ".env")
    plan = upload_plan(app)
    assert plan["git"] is False
    assert plan["files"] == ["app.py"]
    assert reasons(plan) == {".env": "secret file"}
    assert plan["secret_files_not_ignored"] == []


def test_gitignore_fallback_syntax():
    app = new_dir("plain")
    write(app / ".gitignore", "\n".join([
        "# a comment",
        "*.log",
        "!keep.log",
        "tmp/",
        "/root_only.txt",
        "docs/**/draft.md",
        "**/generated",
        "\\#literal",
    ]) + "\n")
    for rel in ["a.py", "x.log", "keep.log", "tmp/t.py", "sub/tmp/t.py", "root_only.txt", "sub/root_only.txt",
                "docs/draft.md", "docs/a/b/draft.md", "docs/final.md", "src/generated/g.py", "#literal",
                "# a comment", "sub/.gitignore", "sub/local.txt", "sub/other.txt", "tmp.txt"]:
        write(app / rel)
    write(app / "sub" / ".gitignore", "local.txt\n!x.log\n")
    write(app / "sub" / "x.log")
    listing = gitignore_listing(app)
    assert listing["git"] is False
    files, ignored = set(listing["candidates"]), set(listing["ignored"])
    assert {"a.py", "keep.log", "sub/root_only.txt", "docs/final.md", "# a comment", "sub/other.txt", "tmp.txt",
            "sub/x.log", ".gitignore", "sub/.gitignore"} <= files, files
    assert {"x.log", "tmp/", "sub/tmp/", "root_only.txt", "docs/draft.md", "docs/a/b/draft.md",
            "src/generated/", "#literal", "sub/local.txt"} == ignored, ignored


def test_poc_style_folder_without_git():
    app = new_dir("poc")
    write(app / "app.py")
    write(app / "Dockerfile")
    write(app / ".appledger" / "report.html")  # our own output: never sent
    write(app / "id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
    plan = upload_plan(app)
    assert sorted(plan["files"]) == ["Dockerfile", "app.py"]
    assert reasons(plan) == {"id_rsa": "secret file"}


if __name__ == "__main__":
    run_all(dict(globals()))
