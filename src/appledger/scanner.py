"""AppLedger honest check: independent scanners, explained in plain language.

Runs Trivy (dependencies, secrets, container setup), Opengrep (code patterns) and,
optionally, SonarQube on an app folder, and turns the findings into feedback a
non-developer can act on:

    report.html     what is wrong, why it matters, what to do, in plain words
    fix-prompt.md   a ready-made request for the coding agent that built the app
    findings.json   normalized findings

Everything runs on this computer. Nothing is uploaded.

Tool locations (all optional):
    APPLEDGER_TRIVY            path to trivy            (default: on PATH, then ~/.appledger/tools)
    APPLEDGER_OPENGREP         path to opengrep         (default: on PATH, then ~/.appledger/tools)
    APPLEDGER_OPENGREP_RULES   opengrep-rules checkout  (default: ~/.appledger/opengrep-rules)
    APPLEDGER_SONAR_URL, APPLEDGER_SONAR_TOKEN, APPLEDGER_SONAR_PROJECT   read results from a SonarQube server
"""

import argparse
import base64
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from packaging.version import Version, InvalidVersion
except ImportError:  # packaging is optional; fall back to string order
    Version = None

APPLEDGER_HOME = Path(os.environ.get("APPLEDGER_HOME", Path.home() / ".appledger"))
OUTPUT_DIR_NAME = ".appledger"
SKIP_DIRS = {".git", ".appledger", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


class ScanError(RuntimeError):
    """A scanner is missing or failed; the message says what to do."""


def find_tool(env_var, names):
    """Return the first existing tool path from an env var, PATH, or ~/.appledger/tools."""
    if os.environ.get(env_var):
        return os.environ[env_var]
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for name in names:
        candidate = APPLEDGER_HOME / "tools" / name
        if candidate.exists():
            return str(candidate)
    return None


def app_files(app_dir):
    app_dir = Path(app_dir)
    for path in app_dir.rglob("*"):
        if path.is_file() and not SKIP_DIRS.intersection(path.relative_to(app_dir).parts[:-1]):
            yield path


# Plain-language levels. "blocker" stops sharing beyond the builder.
LEVELS = {
    "blocker": {"label": "Fix before sharing", "rank": 0},
    "important": {"label": "Fix soon", "rank": 1},
    "minor": {"label": "Good to know", "rank": 2},
}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_TO_LEVEL = {
    "CRITICAL": "blocker", "BLOCKER": "blocker",
    "HIGH": "important", "MAJOR": "important",
    "MEDIUM": "minor", "LOW": "minor", "MINOR": "minor", "INFO": "minor", "UNKNOWN": "minor",
}

SECRET_NAMES = {
    "stripe-secret-token": ("a live Stripe payment key",
                            "can take payments, issue refunds and read your customers' payment details"),
    "slack-web-hook": ("a Slack posting address",
                       "can post messages into your company Slack as if they were your app"),
    "aws-access-key-id": ("an Amazon Web Services key",
                          "can use your cloud account and run up your bill"),
    "github-pat": ("a GitHub access token", "can read or change your company's code"),
    "private-key": ("a private encryption key", "can impersonate your servers"),
}

# What a class of weakness lets an attacker do, in everyday words (by CWE id).
CWE_IMPACT = {
    "CWE-79": "inject their own content or scripts into your pages",
    "CWE-94": "run their own code on your server",
    "CWE-502": "run their own code on your server",
    "CWE-78": "run commands on your server",
    "CWE-89": "read or change anything in your database",
    "CWE-22": "read files on your server they should never see",
    "CWE-200": "see information that should stay private",
    "CWE-400": "slow down or crash your app",
    "CWE-1333": "slow down or crash your app",
    "CWE-770": "slow down or crash your app",
    "CWE-601": "send your users to a fake site that looks like yours",
    "CWE-295": "intercept traffic between your app and other services",
    "CWE-113": "tamper with what your app sends back to users",
    "CWE-93": "tamper with what your app sends back to users",
    "CWE-20": "send unexpected input that makes your app misbehave",
    "CWE-863": "get into parts of the app they shouldn't",
    "CWE-284": "get into parts of the app they shouldn't",
    "CWE-668": "see information that should stay private",
}

MISCONFIG_TEXT = {
    "DS-0001": ("Your app's foundation is not pinned to a version",
                "The Dockerfile uses a ':latest' base image, so it can change without warning and break or weaken your app.",
                "Pin the base image to a specific version, for example python:3.12-slim."),
    "DS-0002": ("Your app runs with full administrator rights",
                "If anyone breaks into the app, they get full control of the machine it runs on.",
                "Run the app as a regular, limited user inside the container."),
    "DS-0026": ("Nobody will notice if your app stops responding",
                "There is no health check, so the platform can't tell when the app hangs.",
                "Add a health check that calls a simple page of the app."),
}

# SonarQube rules (Python) translated into everyday language.
SONAR_TEXT = {
    "python:S2077": ("Someone could read or change your whole database",
                     "Text typed by users goes straight into a database query (SQL injection)."),
    "python:S3649": ("Someone could read or change your whole database",
                     "Text typed by users goes straight into a database query (SQL injection)."),
    "python:S4721": ("Someone could run commands on your server",
                     "User input is passed to a system command."),
    "python:S2076": ("Someone could run commands on your server",
                     "User input is passed to a system command."),
    "python:S4507": ("Debug mode is switched on",
                     "Debug mode shows internal details to anyone and can let them run code on your server."),
    "python:S4830": ("Your app doesn't check who it's talking to",
                     "Certificate checks are turned off, so traffic to other services can be intercepted."),
    "python:S5332": ("Data is sent without encryption",
                     "Using plain http lets others on the network read the data."),
    "python:S6418": ("A password or key is written into the code",
                     "Anyone with the code can use it."),
    "python:S2068": ("A password is written into the code",
                     "Anyone with the code can use it."),
    "python:S5852": ("Some inputs could freeze your app",
                     "A text pattern can be made to run for a very long time."),
    "python:S4423": ("Weak encryption is used", "The protection can be broken."),
    "python:S5131": ("Someone could inject content into your pages",
                     "User input is shown back without being cleaned (cross-site scripting)."),
    "python:S4502": ("Other websites could act on your users' behalf",
                     "Protection against cross-site request forgery is missing, so a malicious page "
                     "could make a logged-in colleague's browser change data in your app."),
    "python:S8392": ("Your app accepts connections from any network",
                     "It listens on every network interface, so anyone who can reach the machine can use it."),
    "python:S930": ("This line will crash when it runs",
                    "A function is called with a missing argument. Here it's the unsafe yaml.load: "
                    "use yaml.safe_load instead."),
    "python:S6965": ("Pages accept more kinds of requests than needed",
                     "Routes don't say which request types they allow, which widens what an attacker can try."),
    "python:S1135": ("A to-do note was left in the code",
                     "Someone planned to finish something here and didn't."),
    "docker:S6596": MISCONFIG_TEXT["DS-0001"][:2],
    "docker:S6471": MISCONFIG_TEXT["DS-0002"][:2],
    "docker:S6470": ("Everything in the folder gets copied into the app",
                     "Files like passwords, local databases or notes may end up inside the published app."),
}


# Where SonarQube's own severity misjudges the risk for an internal app built by a non-developer.
SONAR_LEVEL = {
    "python:S4507": "important",  # Flask debug mode on a shared app lets visitors run code
    "python:S4502": "important",
    "python:S4830": "important",
    "python:S8392": "important",
    "docker:S6470": "important",
    "python:S6965": "minor",
}

SONAR_FIX = {
    "python:S4502": "Turn on CSRF protection for forms and other requests that change data.",
    "python:S8392": "Let AppLedger expose the app instead of listening on all networks: bind to 127.0.0.1.",
    "python:S930": "Replace yaml.load(...) with yaml.safe_load(...).",
    "python:S6965": "List the request types each page needs, for example methods=[\"GET\"].",
    "python:S1135": "Finish the task in the note, or remove the note.",
    "python:S4507": "Switch debug mode off before sharing the app.",
    "python:S4830": "Remove verify=False so certificates are checked again.",
    "docker:S6596": MISCONFIG_TEXT["DS-0001"][2],
    "docker:S6471": MISCONFIG_TEXT["DS-0002"][2],
    "docker:S6470": "Copy only the files the app needs, and add a .dockerignore for the rest.",
}


def parse_version(v):
    v = (v or "").strip()
    if Version:
        try:
            return Version(v)
        except InvalidVersion:
            pass
    return v


def safest_fix(fixed_versions):
    """Highest of the smallest fixed version of each vulnerability."""
    per_vuln = []
    for fv in fixed_versions:
        options = [parse_version(x) for x in fv.split(",") if x.strip()]
        if options:
            try:
                per_vuln.append(min(options))
            except TypeError:
                per_vuln.append(options[0])
    if not per_vuln:
        return None
    try:
        return str(max(per_vuln))
    except TypeError:
        return str(per_vuln[-1])


def run_trivy(app_dir):
    trivy = find_tool("APPLEDGER_TRIVY", ["trivy", "trivy.exe"])
    if not trivy:
        raise ScanError("Trivy is not installed. Install it from https://trivy.dev "
                        "(Windows: winget install AquaSecurity.Trivy, Mac: brew install trivy).")
    skip = [arg for d in sorted(SKIP_DIRS) for arg in ("--skip-dirs", d)]
    proc = subprocess.run(
        [trivy, "fs", "--quiet", "--scanners", "vuln,secret,misconfig", *skip,
         "--format", "json", str(app_dir)],
        capture_output=True, text=True, encoding="utf-8", stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise ScanError("Trivy failed:\n" + proc.stderr.strip()[-1500:])
    return json.loads(proc.stdout)


def findings_from_trivy(data):
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")

        for s in result.get("Secrets") or []:
            name, power = SECRET_NAMES.get(
                s["RuleID"], (s.get("Title", "a password or key"), "can use it as if they were you"))
            findings.append({
                "source": "Trivy", "kind": "secret", "level": "blocker",
                "title": f"Your code contains {name}",
                "why": f"Anyone who can see this file {power}. It's written in plain text on line "
                       f"{s.get('StartLine')} of {target}.",
                "fix": "Remove it from the code, store it in the platform's secret store, and "
                       "create a new key: treat the old one as leaked.",
                "where": f"{target}:{s.get('StartLine')}",
                "technical": f"{s['RuleID']} ({s['Severity']})",
            })

        for m in result.get("Misconfigurations") or []:
            title, why, fix = MISCONFIG_TEXT.get(
                m["ID"], (m.get("Title", "Configuration problem"), m.get("Description", ""), m.get("Resolution", "")))
            findings.append({
                "source": "Trivy", "kind": "setup", "level": SEVERITY_TO_LEVEL.get(m["Severity"], "minor"),
                "title": title, "why": why, "fix": fix, "where": target,
                "technical": f"{m['ID']} {m.get('Title', '')} ({m['Severity']})",
            })

        by_pkg = defaultdict(list)
        for v in result.get("Vulnerabilities") or []:
            by_pkg[(v["PkgName"], v["InstalledVersion"])].append(v)
        for (pkg, installed), vulns in by_pkg.items():
            counts = defaultdict(int)
            impacts = []
            # Describe the worst problems first; generic input-validation wording goes last.
            vulns.sort(key=lambda v: SEVERITY_RANK.get(v["Severity"], 9))
            for v in vulns:
                counts[v["Severity"]] += 1
                text = (v.get("Title", "") + " " + v.get("Description", "")).lower()
                if "code execution" in text or "execute arbitrary" in text:
                    impact = CWE_IMPACT["CWE-94"]
                    if impact not in impacts:
                        impacts.append(impact)
                for cwe in v.get("CweIDs") or []:
                    impact = CWE_IMPACT.get(cwe)
                    if impact and impact not in impacts:
                        impacts.append(impact)
            generic = CWE_IMPACT["CWE-20"]
            if generic in impacts and len(impacts) > 1:
                impacts.remove(generic)
            worst = min((SEVERITY_TO_LEVEL.get(s, "minor") for s in counts),
                        key=lambda lvl: LEVELS[lvl]["rank"])
            target_version = safest_fix([v.get("FixedVersion", "") for v in vulns])
            serious = counts["CRITICAL"] + counts["HIGH"]
            n = len(vulns)
            why = (f"Version {installed} has {n} known security problem{'s' if n != 1 else ''}"
                   + (f", {serious} of them serious" if serious else "") + ".")
            if impacts:
                why += " At worst, an attacker could " + "; or ".join(impacts[:3]) + "."
            findings.append({
                "source": "Trivy", "kind": "outdated", "level": worst,
                "title": f"{pkg} is out of date",
                "why": why,
                "fix": (f"Update {pkg} to {target_version} or newer, then test the app."
                        if target_version else f"Replace {pkg}: no fixed version is published yet."),
                "where": target,
                "technical": ", ".join(sorted(v["VulnerabilityID"] for v in vulns)[:6])
                             + (" …" if n > 6 else ""),
            })
    return findings


# Opengrep (the open-source fork of Semgrep) with rule folders picked per language found in the app.
RULES_BY_SUFFIX = {
    ".py": ["python/lang/security", "python/flask", "python/django", "python/fastapi", "python/requests",
            "python/sqlalchemy", "python/jwt"],
    ".js": ["javascript/lang/security", "javascript/express", "javascript/browser"],
    ".jsx": ["javascript/lang/security", "javascript/react"],
    ".ts": ["typescript", "javascript/lang/security", "javascript/express"],
    ".tsx": ["typescript/react", "javascript/lang/security"],
    ".php": ["php/lang/security"],
    ".go": ["go/lang/security"],
    ".java": ["java/lang/security", "java/spring"],
    ".rb": ["ruby/lang/security", "ruby/rails"],
    ".tf": ["terraform"],
}
ALWAYS_RULES = ["generic/secrets"]

# Opengrep secret rules mapped to the matching Trivy rule, so both name the secret the same way.
CODE_SECRET_RULES = {"detected-stripe-api-key": "stripe-secret-token", "stripe-access-token": "stripe-secret-token",
                     "detected-slack-webhook": "slack-web-hook", "slack-webhook-url": "slack-web-hook",
                     "detected-aws-access-key-id-value": "aws-access-key-id", "detected-github-token": "github-pat"}

# (match on rule id or CWE) -> (title, why, fix, level). First match wins.
CODE_TEXT = [
    (("sql",), ("Someone could read or change your whole database",
                "Text typed by users goes straight into a database query (SQL injection).",
                "Use query parameters instead of gluing user text into SQL.", "blocker")),
    (("CWE-78:", "subprocess", "command-injection"),
     ("Someone could run commands on your server", "User input is passed to a system command.",
      "Never pass user input to the shell. Use a fixed list of arguments and check the input first.", "blocker")),
    (("CWE-502:", "deserializ", "pyyaml", "pickle"),
     ("Someone could run their own code through uploaded data",
      "The app turns untrusted input back into objects in an unsafe way.",
      "Use a safe loader, for example yaml.safe_load or plain JSON.", "blocker")),
    (("CWE-79:", "xss"), ("Someone could inject content into your pages",
                          "User input is shown back without being cleaned (cross-site scripting).",
                          "Escape user input before showing it, or use the template engine's auto-escaping.", "important")),
    (("CWE-22:", "path-traversal"), ("Someone could read files on your server",
                                     "User input is used to build a file path.",
                                     "Only allow known file names, never paths typed by users.", "important")),
    (("CWE-668:", "bad_host", "bind"), (SONAR_TEXT["python:S8392"][0], SONAR_TEXT["python:S8392"][1],
                                        "Let AppLedger expose the app instead of listening on all networks: bind to 127.0.0.1.",
                                        "important")),
    (("CWE-489:", "debug"), (SONAR_TEXT["python:S4507"][0], SONAR_TEXT["python:S4507"][1],
                             "Switch debug mode off before sharing the app.", "important")),
    (("CWE-295:", "verify", "cert"), (SONAR_TEXT["python:S4830"][0], SONAR_TEXT["python:S4830"][1],
                                      "Remove verify=False so certificates are checked again.", "important")),
    (("missing-user", "CWE-250:", "CWE-269:"), (MISCONFIG_TEXT["DS-0002"][0], MISCONFIG_TEXT["DS-0002"][1],
                                                MISCONFIG_TEXT["DS-0002"][2], "important")),
    (("latest-version",), (*MISCONFIG_TEXT["DS-0001"], "minor")),
    (("source-not-pinned",), ("Your app's foundation can change between builds",
                              "The base image is named by a version tag, which its publisher can move to a new build.",
                              "Pin the base image to an exact build (its sha256 digest) when the app becomes important.",
                              "minor")),
    (("json-notation",), ("A start-up command could behave unexpectedly",
                          "The command is written as plain text instead of a list, so the shell may change it.",
                          "Write the command as a list, for example [\"python\", \"app.py\"].", "minor")),
    (("use-timeout",), ("Calls to other services can hang forever",
                        "A web request has no time limit, so one slow service can freeze your app.",
                        "Add a timeout to every outgoing request, for example timeout=10.", "minor")),
    (("raise-for-status",), ("Failed calls to other services go unnoticed",
                             "The app doesn't check whether a web request succeeded.",
                             "Check the response status and handle errors.", "minor")),
    (("no-cache-dir",), ("The app package is bigger than it needs to be",
                         "Installer caches are kept inside the container.",
                         "Add --no-cache-dir to pip install.", "minor")),
]


# Audit rules whose pattern is a problem by itself, whatever the input (e.g. verify=False).
DANGEROUS_ON_SIGHT = {"disabled-cert-validation"}


def opengrep_rules_root():
    return Path(os.environ.get("APPLEDGER_OPENGREP_RULES", APPLEDGER_HOME / "opengrep-rules"))


def rule_folders(app_dir):
    files = list(app_files(app_dir))
    folders = list(ALWAYS_RULES)
    for suffix in sorted({p.suffix.lower() for p in files}):
        folders += RULES_BY_SUFFIX.get(suffix, [])
    if any(p.name.lower() == "dockerfile" or p.name.lower().endswith(".dockerfile") for p in files):
        folders.append("dockerfile")
    return [f for f in dict.fromkeys(folders) if (opengrep_rules_root() / f).exists()]


def rule_pack(app_dir):
    """Merge the rule folders this app needs into one cached file.

    Opengrep spends most of its time loading hundreds of small rule files; one merged
    file makes a scan about ten times faster.
    """
    import yaml  # only needed when a pack has to be built

    folders = rule_folders(app_dir)
    key = hashlib.sha256(("v2|" + "|".join(folders)).encode()).hexdigest()[:12]
    pack = APPLEDGER_HOME / "cache" / f"rules-{key}.yaml"
    if pack.exists():
        return pack
    rules = []
    for folder in folders:
        for f in sorted((opengrep_rules_root() / folder).rglob("*.yaml")):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError):
                continue
            if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
                # Rule ids are only unique per file; prefix them with their path the way Opengrep
                # does, or same-named rules from different folders silently replace each other.
                prefix = ".".join(f.relative_to(opengrep_rules_root()).parent.parts)
                for rule in doc["rules"]:
                    if isinstance(rule, dict) and "id" in rule:
                        rules.append({**rule, "id": f"{prefix}.{rule['id']}"})
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False), encoding="utf-8")
    return pack


def run_opengrep(app_dir):
    opengrep = find_tool("APPLEDGER_OPENGREP", ["opengrep", "opengrep.exe", "opengrep_windows_x86.exe"])
    if not opengrep:
        raise ScanError("Opengrep is not installed. Download it from "
                        "https://github.com/opengrep/opengrep/releases, or set APPLEDGER_OPENGREP to its path.")
    if not opengrep_rules_root().exists():
        raise ScanError(f"Opengrep rules not found at {opengrep_rules_root()}. Run: git clone --depth 1 "
                        f"https://github.com/opengrep/opengrep-rules.git \"{opengrep_rules_root()}\"")
    excludes = [arg for d in sorted(SKIP_DIRS) for arg in ("--exclude", d)]
    proc = subprocess.run([opengrep, "scan", "--config", str(rule_pack(app_dir)), *excludes,
                           "--json", "--quiet", str(app_dir)],
                          capture_output=True, text=True, encoding="utf-8", stdin=subprocess.DEVNULL)
    if not proc.stdout.strip():
        raise ScanError("Opengrep failed:\n" + proc.stderr.strip()[-1500:])
    data = json.loads(proc.stdout)
    for err in data.get("errors", []):
        print("Opengrep warning:", err.get("message", "")[:200], file=sys.stderr)
    return data


def findings_from_opengrep(data, app_dir):
    findings = []
    for r in data.get("results", []):
        rule = r["check_id"].rsplit(".", 1)[-1]
        meta = r["extra"].get("metadata", {})
        try:
            path = Path(r["path"]).resolve().relative_to(Path(app_dir).resolve()).as_posix()
        except ValueError:
            path = r["path"]
        where = f"{path}:{r['start']['line']}"
        technical = f"{rule} ({r['extra'].get('severity', '')})"
        if rule in CODE_SECRET_RULES:
            name, power = SECRET_NAMES[CODE_SECRET_RULES[rule]]
            findings.append({
                "source": "Opengrep", "kind": "secret", "level": "blocker",
                "title": f"Your code contains {name}",
                "why": f"Anyone who can see this file {power}. It's written in plain text on line "
                       f"{r['start']['line']} of {path}.",
                "fix": "Remove it from the code, store it in the platform's secret store, and "
                       "create a new key: treat the old one as leaked.",
                "where": where, "technical": technical,
            })
            continue
        cwe = meta.get("cwe") or []
        haystack = " ".join([r["check_id"].lower()] + ([cwe] if isinstance(cwe, str) else list(cwe)))
        for keys, (title, why, fix, level) in CODE_TEXT:
            if any(k.lower() in haystack for k in keys):
                break
        else:
            message = r["extra"].get("message", rule).strip()
            title, why, fix = message.split(". ")[0], message, message
            level = {"ERROR": "important", "WARNING": "important"}.get(r["extra"].get("severity"), "minor")
        finding = {"source": "Opengrep", "kind": "security", "level": level, "title": title,
                   "why": why, "fix": fix, "where": where, "technical": technical, "topic": title}
        # Audit rules flag patterns that are only dangerous if user input reaches them. Shown as hard
        # findings they would mostly be false alarms, so they become hints a reviewer can check.
        if ("audit" in (meta.get("subcategory") or []) and meta.get("confidence") == "LOW"
                and rule not in DANGEROUS_ON_SIGHT):
            finding.update(level="minor", title=f"Worth a look: {title[0].lower()}{title[1:]}",
                           why="This code pattern is only risky if text from users or other systems can reach "
                               "it. Check that it can't. " + why)
        findings.append(finding)
    return findings


def sonar_get(base, token, path):
    req = urllib.request.Request(base.rstrip("/") + path)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def fetch_sonar(base, token, project):
    issues = sonar_get(base, token, f"/api/issues/search?componentKeys={project}&resolved=false&ps=500")
    hotspots = sonar_get(base, token, f"/api/hotspots/search?projectKey={project}&ps=500")
    return issues, hotspots


def findings_from_sonar(issues, hotspots):
    findings = []
    for i in issues.get("issues", []):
        title, why = SONAR_TEXT.get(i["rule"], (i["message"], ""))
        sev = i.get("severity", "MINOR")
        level = SONAR_LEVEL.get(i["rule"], SEVERITY_TO_LEVEL.get(sev, "minor"))
        kind = "security" if i.get("type") == "VULNERABILITY" else "quality"
        if kind == "quality" and level == "blocker":
            level = "important"  # code-quality problems never block sharing on their own
        findings.append({
            "source": "SonarQube", "kind": kind, "level": level,
            "title": title, "why": why or i["message"],
            "fix": SONAR_FIX.get(i["rule"], i["message"]),
            "where": f"{i['component'].split(':', 1)[-1]}:{i.get('line', '')}",
            "technical": f"{i['rule']} ({sev})",
        })
    for h in hotspots.get("hotspots", []):
        title, why = SONAR_TEXT.get(h["ruleKey"], (h["message"], ""))
        prob = h.get("vulnerabilityProbability", "LOW")
        level = {"HIGH": "blocker", "MEDIUM": "important"}.get(prob, "minor")
        findings.append({
            "source": "SonarQube", "kind": "security", "level": level,
            "title": title, "why": why or h["message"], "fix": h["message"],
            "where": f"{h['component'].split(':', 1)[-1]}:{h.get('line', '')}",
            "technical": f"{h['ruleKey']} (hotspot, {prob} risk)",
        })
    return findings


def dedupe(findings):
    """Keep one finding per (title, file): two scanners often report the same thing."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: LEVELS[f["level"]]["rank"]):
        key = (f.get("topic", f["title"]), f["where"].split(":")[0])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def tier_verdicts(findings):
    blockers = sum(f["level"] == "blocker" for f in findings)
    important = sum(f["level"] == "important" for f in findings)
    return [
        ("Personal", "Only you", True, "Allowed. You'll see these warnings."),
        ("Team", "A named team", blockers == 0,
         "Allowed." if blockers == 0 else f"Blocked by {blockers} problem{'s' if blockers != 1 else ''} marked 'Fix before sharing'."),
        ("Company", "Everyone at the company", blockers == 0 and important == 0,
         "Allowed." if blockers == 0 and important == 0
         else "Needs all 'Fix before sharing' and 'Fix soon' items resolved, then a review."),
    ]


def health_score(findings):
    """Each problem removes a share of what's left, so scores stay comparable at the low end."""
    keep = {"blocker": 0.75, "important": 0.93, "minor": 0.99}
    score = 100.0
    for f in findings:
        score *= keep[f["level"]]
    return round(score)


def write_fix_prompt(findings, app_name, scanners, path):
    lines = [
        f"# Fix request from AppLedger for \"{app_name}\"",
        "",
        f"Independent scanners ({', '.join(scanners)}) found the problems below. Fix them in order.",
        "Keep the app's behaviour the same for its users. After each fix, explain the change in one",
        "plain sentence a non-developer understands. When done, ask me to run the AppLedger scan again.",
        "",
    ]
    for n, f in enumerate([f for f in findings if f["level"] != "minor"], 1):
        lines += [f"## {n}. {f['title']}  [{LEVELS[f['level']]['label']}]",
                  f"- Where: `{f['where']}`",
                  f"- Problem: {f['why']}",
                  f"- Expected fix: {f['fix']}",
                  f"- Scanner detail: {f['technical']}",
                  ""]
    minor = [f for f in findings if f["level"] == "minor"]
    if minor:
        lines += ["## Also, if time allows", ""]
        lines += [f"- {f['title']} (`{f['where']}`): {f['fix']}" for f in minor]
        lines.append("")
    lines += ["## Rules",
              "- Never put passwords, keys or tokens in code. Read them from environment variables.",
              "- Any key that was in the code must be treated as leaked: tell me to rotate it.",
              "- Don't remove features to make a warning go away. Ask me if a fix changes behaviour."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def usage_section(usage):
    """HTML for the 'AI effort' part of the report, or '' when no agent logs were found."""
    if not usage:
        return ""
    e = html.escape
    rows = []
    for tool in usage["tools"]:
        here = tool["this_folder"]
        if not here:
            continue
        for model, v in here["by_model"].items():
            cost = f"${v['cost_usd']:,.2f}" if v.get("cost_usd") else "not priced"
            rows.append(f"<tr><td>{e(tool['tool'])}</td><td>{e(model)}</td><td>{v['messages']:,}</td>"
                        f"<td>{v['input'] + v['cache_write'] + v['cache_read'] + v['output']:,}</td><td>{cost}</td></tr>")
    parent = [t["parent_folders"] for t in usage["tools"] if t.get("parent_folders")]
    parent_note = (f"<p class=\"tech\">Another {sum(p['tokens_total'] for p in parent):,} tokens "
                   f"(${sum(p['cost_usd'] for p in parent):,.2f}) were used in sessions started in a parent folder; "
                   "they may include other work, so they're not counted above.</p>") if parent else ""
    return f"""
  <section class="usage">
    <h2>AI effort that went into this app</h2>
    <p><strong>{usage['tokens_total']:,} tokens</strong> over {usage['sessions']} session{'s' if usage['sessions'] != 1 else ''},
       worth about <strong>${usage['cost_usd']:,.2f}</strong> at API list prices.</p>
    <table><thead><tr><th>Tool</th><th>Model</th><th>Replies</th><th>Tokens</th><th>Est. cost</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>
    <p class="tech">{e(usage['note'])} Prices: {e(usage['prices'])}.</p>{parent_note}
  </section>"""


def write_report(findings, app_name, scanners, path, usage=None):
    e = html.escape
    score = health_score(findings)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 30 else "F"
    counts = {lvl: sum(f["level"] == lvl for f in findings) for lvl in LEVELS}
    cards = []
    for f in findings:
        cards.append(f"""
      <article class="finding {f['level']}" {'data-minor' if f['level'] == 'minor' else ''}>
        <div class="tag">{e(LEVELS[f['level']]['label'])}</div>
        <h3>{e(f['title'])}</h3>
        <p>{e(f['why'])}</p>
        <p class="do"><strong>What to do:</strong> {e(f['fix'])}</p>
        <p class="tech">{e(f['source'])} · {e(f['where'])} · {e(f['technical'])}</p>
      </article>""")
    tiers = "".join(
        f"<li class=\"{'ok' if ok else 'no'}\"><strong>{e(name)}</strong><span>{e(who)}</span><em>{e(msg)}</em></li>"
        for name, who, ok, msg in tier_verdicts(findings))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(app_name)} · AppLedger check</title>
<style>
:root {{ --bg:#f5f7f4; --surface:#fff; --ink:#18221b; --muted:#5b6a5f; --line:#dde4dd;
  --block:#b42318; --block-soft:#fdeceb; --imp:#9a5b00; --imp-soft:#fdf3e1; --minor:#4b5d52; --minor-soft:#eef2ee;
  --ok:#1e7a46; --accent:#2f6b3f; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111713; --surface:#18201b; --ink:#e6ede7; --muted:#9aaa9f; --line:#2a352d;
  --block:#ff8a80; --block-soft:#3b1a17; --imp:#f2b95a; --imp-soft:#33280f; --minor:#a7b8ad; --minor-soft:#1f2923;
  --ok:#6bd39a; --accent:#7fc694; color-scheme: dark; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif }}
main {{ max-width:860px; margin:0 auto; padding:32px 18px 64px; display:flex; flex-direction:column; gap:28px }}
h1,h2,h3 {{ margin:0; line-height:1.2 }} p {{ margin:0 }}
.eyebrow {{ font:600 12px/1 ui-monospace,Consolas,monospace; letter-spacing:.08em; text-transform:uppercase; color:var(--muted) }}
.summary {{ display:grid; grid-template-columns:auto 1fr; gap:24px; align-items:center; background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:22px }}
.grade {{ width:92px; height:92px; border-radius:50%; display:grid; place-items:center; font:700 44px/1 system-ui; border:6px solid var(--accent); color:var(--accent) }}
.counts {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px }}
.pill {{ padding:3px 10px; border-radius:99px; font-size:13px; font-weight:600 }}
.pill.blocker {{ background:var(--block-soft); color:var(--block) }} .pill.important {{ background:var(--imp-soft); color:var(--imp) }} .pill.minor {{ background:var(--minor-soft); color:var(--minor) }}
.tiers {{ list-style:none; margin:0; padding:0; display:grid; gap:8px }}
.tiers li {{ display:grid; grid-template-columns:110px 170px 1fr; gap:12px; padding:12px 14px; border-radius:8px; background:var(--surface); border:1px solid var(--line); align-items:baseline }}
.tiers li.ok strong {{ color:var(--ok) }} .tiers li.no strong {{ color:var(--block) }}
.tiers span {{ color:var(--muted); font-size:14px }} .tiers em {{ font-style:normal; font-size:14px }}
.finding {{ background:var(--surface); border:1px solid var(--line); border-left:5px solid var(--minor); border-radius:8px; padding:16px 18px; display:flex; flex-direction:column; gap:8px }}
.finding.blocker {{ border-left-color:var(--block) }} .finding.important {{ border-left-color:var(--imp) }}
.tag {{ font:600 12px/1 ui-monospace,Consolas,monospace; text-transform:uppercase; letter-spacing:.06em; color:var(--muted) }}
.finding.blocker .tag {{ color:var(--block) }} .finding.important .tag {{ color:var(--imp) }}
.do {{ font-size:15px }} .tech {{ font:12px/1.4 ui-monospace,Consolas,monospace; color:var(--muted); overflow-wrap:anywhere }}
.list {{ display:flex; flex-direction:column; gap:12px }}
.hidden-minor [data-minor] {{ display:none }}
button {{ font:inherit; padding:8px 14px; border-radius:6px; border:1px solid var(--line); background:var(--surface); color:var(--ink); cursor:pointer }}
button:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px }}
.fixbox {{ background:var(--surface); border:1px dashed var(--accent); border-radius:10px; padding:18px; display:flex; flex-direction:column; gap:10px }}
.usage {{ background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:18px; display:flex; flex-direction:column; gap:10px; overflow-x:auto }}
.usage table {{ border-collapse:collapse; width:100%; min-width:460px; font-size:14px; font-variant-numeric:tabular-nums }}
.usage th, .usage td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line) }}
.usage th {{ font:600 11px/1 ui-monospace,Consolas,monospace; text-transform:uppercase; letter-spacing:.06em; color:var(--muted) }}
@media (max-width:620px) {{ .summary {{ grid-template-columns:1fr }} .tiers li {{ grid-template-columns:1fr; gap:2px }} }}
</style></head>
<body><main>
  <div><span class="eyebrow">AppLedger honest check · {e(datetime.now().strftime('%d %b %Y %H:%M'))}</span>
  <h1>{e(app_name)}</h1></div>
  <section class="summary">
    <div class="grade" aria-label="Health grade {grade}" style="{'' if grade in 'AB' else 'border-color:var(--block);color:var(--block)' if grade in 'DF' else 'border-color:var(--imp);color:var(--imp)'}">{grade}</div>
    <div><h2>Health score {score} / 100</h2>
      <p>Checked by {e(' and '.join(scanners))}, independently of the AI that wrote the code.</p>
      <div class="counts">
        <span class="pill blocker">{counts['blocker']} fix before sharing</span>
        <span class="pill important">{counts['important']} fix soon</span>
        <span class="pill minor">{counts['minor']} good to know</span>
      </div></div>
  </section>
  <section><h2 style="margin-bottom:12px">Who can use it right now</h2><ul class="tiers">{tiers}</ul></section>{usage_section(usage)}
  <section class="fixbox">
    <h2>Fix it for me</h2>
    <p>AppLedger wrote a fix request for the coding agent that built this app (Claude Code, Cursor, Codex…). Open <code>fix-prompt.md</code>, paste it into the agent, then run the check again.</p>
  </section>
  <section>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px">
      <h2>What we found</h2>
      <button type="button" id="toggle">Show the {counts['minor']} minor items</button>
    </div>
    <div class="list hidden-minor" id="list">{''.join(cards)}</div>
  </section>
</main>
<script>
const list = document.getElementById('list'), btn = document.getElementById('toggle');
btn.addEventListener('click', () => {{
  const hidden = list.classList.toggle('hidden-minor');
  btn.textContent = hidden ? 'Show the {counts['minor']} minor items' : 'Hide minor items';
}});
</script>
</body></html>"""
    Path(path).write_text(page, encoding="utf-8")


def doctor():
    """Which scanners are available, and how to get the missing ones."""
    return {
        "trivy": find_tool("APPLEDGER_TRIVY", ["trivy", "trivy.exe"]),
        "opengrep": find_tool("APPLEDGER_OPENGREP", ["opengrep", "opengrep.exe", "opengrep_windows_x86.exe"]),
        "opengrep_rules": str(opengrep_rules_root()) if opengrep_rules_root().exists() else None,
        "sonarqube": os.environ.get("APPLEDGER_SONAR_URL"),
    }


def ai_usage_for(app_dir):
    """Token use and cost from local agent logs; never lets a log problem break the check."""
    from .usage import estimate_usage
    try:
        return estimate_usage(app_dir)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def grade_for(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 30 else "F"


def scan(app_dir, sonar_dir=None, code_scan=True):
    """Run the scanners installed on this machine. Returns (findings, scanner names)."""
    app_dir = Path(app_dir).resolve()
    scanners = ["Trivy"]
    findings = findings_from_trivy(run_trivy(app_dir))
    if code_scan:
        findings += findings_from_opengrep(run_opengrep(app_dir), app_dir)
        scanners.append("Opengrep")
    sonar_url, sonar_token = os.environ.get("APPLEDGER_SONAR_URL"), os.environ.get("APPLEDGER_SONAR_TOKEN")
    if sonar_dir:
        sonar_dir = Path(sonar_dir)
        findings += findings_from_sonar(json.loads((sonar_dir / "sonar-issues.json").read_text(encoding="utf-8")),
                                        json.loads((sonar_dir / "sonar-hotspots.json").read_text(encoding="utf-8")))
        scanners.append("SonarQube")
    elif sonar_url and sonar_token:
        findings += findings_from_sonar(*fetch_sonar(sonar_url, sonar_token,
                                                     os.environ.get("APPLEDGER_SONAR_PROJECT", app_dir.name)))
        scanners.append("SonarQube")
    return dedupe(findings), scanners


def check(app_dir, out_dir=None, app_name=None, sonar_dir=None, code_scan=True, mode=None):
    """Check an app folder and write report.html, fix-prompt.md and findings.json.

    mode "hosted" (the default) sends the project to the AppLedger scanning service, so no
    scanners are needed locally; mode "local" runs Trivy and Opengrep on this machine.
    Set APPLEDGER_MODE to change the default. Results go to <app>/.appledger unless out_dir is given.
    """
    app_dir = Path(app_dir).resolve()
    if not app_dir.is_dir():
        raise ScanError(f"{app_dir} is not a folder.")
    out = Path(out_dir) if out_dir else app_dir / OUTPUT_DIR_NAME
    out.mkdir(parents=True, exist_ok=True)
    app_name = app_name or app_dir.name

    mode = mode or os.environ.get("APPLEDGER_MODE", "hosted")
    if mode == "hosted" and not sonar_dir:
        from .client import hosted_scan
        findings, scanners = hosted_scan(app_dir)
    else:
        findings, scanners = scan(app_dir, sonar_dir, code_scan)

    score = health_score(findings)
    counts = {lvl: sum(f["level"] == lvl for f in findings) for lvl in LEVELS}
    summary = {
        "app": app_name, "score": score, "grade": grade_for(score), "scanners": scanners,
        "counts": {LEVELS[k]["label"]: v for k, v in counts.items()},
        "who_can_use_it": [{"tier": t, "audience": a, "allowed": ok, "note": n}
                           for t, a, ok, n in tier_verdicts(findings)],
        "findings": findings,
        "report": str(out / "report.html"), "fix_prompt": str(out / "fix-prompt.md"),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "ai_usage": ai_usage_for(app_dir),
    }
    (out / "findings.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_fix_prompt(findings, app_name, scanners, out / "fix-prompt.md")
    write_report(findings, app_name, scanners, out / "report.html", summary["ai_usage"])
    (out / ".gitignore").write_text("*\n", encoding="utf-8")  # keep reports out of version control
    return summary


def main():
    ap = argparse.ArgumentParser(prog="appledger", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("app_dir", nargs="?", default=".")
    ap.add_argument("--out", help="where to write the report (default: <app>/.appledger)")
    ap.add_argument("--app-name")
    ap.add_argument("--sonar-dir", help="folder with sonar-issues.json and sonar-hotspots.json")
    ap.add_argument("--no-code-scan", action="store_true", help="skip the Opengrep code scan")
    ap.add_argument("--doctor", action="store_true", help="show which scanners are available")
    ap.add_argument("--ai-cost", action="store_true",
                    help="only show how many AI tokens, and what they'd cost, went into this folder")
    ap.add_argument("--local", action="store_true",
                    help="run Trivy and Opengrep on this machine instead of the AppLedger service")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to a legacy code page

    if args.ai_cost:
        usage = ai_usage_for(Path(args.app_dir).resolve())
        if not usage:
            print("No Claude Code or Codex logs on this computer mention this folder.")
            return
        print(f"{usage['tokens_total']:,} tokens over {usage['sessions']} sessions, "
              f"about ${usage['cost_usd']:,.2f} at API list prices.")
        for tool in usage["tools"]:
            for model, v in (tool["this_folder"] or {}).get("by_model", {}).items():
                print(f"  {tool['tool']:12} {model:22} {v['messages']:>6,} replies  ${v.get('cost_usd', 0):>9,.2f}")
        print(usage["note"])
        return
    if args.doctor:
        for tool, where in doctor().items():
            print(f"{tool:15} {where or 'not found'}")
        return
    try:
        result = check(args.app_dir, args.out, args.app_name, args.sonar_dir, not args.no_code_scan,
                       mode="local" if args.local else None)
    except ScanError as e:
        sys.exit(str(e))
    print(f"{result['app']}: {result['grade']} · score {result['score']}/100 · "
          + " · ".join(f"{v} {k.lower()}" for k, v in result["counts"].items()))
    print(f"Report: {result['report']}")


if __name__ == "__main__":
    main()
