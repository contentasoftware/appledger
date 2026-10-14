"""Run an AppLedger check on a schedule: Task Scheduler on Windows, cron on macOS and Linux.

    python -m appledger path/to/app --schedule daily|weekly|off
    python -m appledger --schedules

Each scheduled check runs at 09:00 as "python -m appledger <folder> --yes --quiet", plus --local
if the schedule was set up in local mode. A hosted schedule needs the user's consent to send
the folder first, given when the schedule is set up. Windows tasks live in the "AppLedger"
folder of Task Scheduler; cron lines end with a "# appledger:<folder>" marker.
"""

import hashlib
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from .scanner import APPLEDGER_HOME, ScanError

TASK_FOLDER = "AppLedger"
CRON_MARKER = "# appledger:"
RUN_AT = "09:00"
CRON_TIMES = {"daily": "0 9 * * *", "weekly": "0 9 * * 1"}
MAX_TASK_COMMAND = 261  # schtasks refuses a longer /TR; a small .cmd file is used instead


def source_pythonpath():
    """The folder holding the appledger package when running from a source checkout, else None.

    A scheduled task doesn't inherit this shell's PYTHONPATH, so it has to be set in the task.
    """
    pkg_parent = Path(__file__).resolve().parent.parent
    if {"site-packages", "dist-packages"}.intersection(pkg_parent.parts):
        return None
    return str(pkg_parent)


def safe_name(app_dir):
    """A task name from the folder name, with a short hash so two folders called "app" don't clash."""
    app_dir = Path(app_dir).resolve()
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", app_dir.name).strip("-.") or "app"
    return f"{name}-{hashlib.sha256(os.path.normcase(str(app_dir)).encode()).hexdigest()[:6]}"


def task_name(app_dir):
    return f"{TASK_FOLDER}\\{safe_name(app_dir)}"


def check_args(app_dir, local=False, extra=()):
    """Arguments after the Python executable for one unattended check."""
    args = ["-m", "appledger", str(Path(app_dir).resolve()), "--yes", "--quiet"]
    if local:
        args.append("--local")
    return args + list(extra)


def windows_quote(arg):
    return f'"{arg}"' if not arg or re.search(r'[\s&|<>^()]', arg) else arg


def windows_command(app_dir, local=False, extra=(), pythonpath=None, python=None):
    """The command Task Scheduler runs (the /TR value)."""
    python = python or sys.executable
    args = check_args(app_dir, local, extra)
    parts = [f'"{python}"', *args[:2], f'"{args[2]}"', *(windows_quote(a.replace('"', "")) for a in args[3:])]
    command = " ".join(parts)
    if pythonpath:
        command = f'cmd /c "set PYTHONPATH={pythonpath}&& {command}"'
    return command


def cron_line(app_dir, frequency, local=False, extra=(), pythonpath=None, python=None):
    """One crontab line, ending with the marker that lets AppLedger find it again."""
    command = " ".join(shlex.quote(a) for a in [python or sys.executable, *check_args(app_dir, local, extra)])
    if pythonpath:
        command = f"PYTHONPATH={shlex.quote(pythonpath)} {command}"
    command = command.replace("%", "\\%")  # cron turns a bare % into a newline
    return f"{CRON_TIMES[frequency]} {command} {CRON_MARKER}{Path(app_dir).resolve()}"


def run(args, input_text=None):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace", input=input_text,  # nosemgrep -- argument list built by this module, no shell
                              stdin=None if input_text is not None else subprocess.DEVNULL)
    except OSError as e:
        raise ScanError(f"Couldn't run {args[0]} to set up the schedule ({e}).")
    return proc


def wrapper_script(app_dir, command):
    """For a command too long for schtasks: write it to ~/.appledger/schedules/<name>.cmd."""
    path = APPLEDGER_HOME / "schedules" / f"{safe_name(app_dir)}.cmd"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"@echo off\r\n{command}\r\n", encoding="utf-8")
    return f'"{path}"'


def windows_schedule(app_dir, frequency, local, extra):
    command = windows_command(app_dir, local, extra, source_pythonpath())
    if len(command) > MAX_TASK_COMMAND:
        command = wrapper_script(app_dir, command)
    proc = run(["schtasks", "/Create", "/F", "/SC", frequency.upper(), "/ST", RUN_AT,
                "/TN", task_name(app_dir), "/TR", command])
    if proc.returncode != 0:
        raise ScanError("Couldn't create the scheduled check: " + (proc.stderr or proc.stdout).strip())
    return command


def read_crontab():
    proc = run(["crontab", "-l"])
    return proc.stdout if proc.returncode == 0 else ""  # no crontab yet


def write_crontab(lines):
    text = "".join(line + "\n" for line in lines)
    proc = run(["crontab", "-"], input_text=text)
    if proc.returncode != 0:
        raise ScanError("Couldn't update your crontab: " + proc.stderr.strip())


def without_folder(crontab, app_dir):
    marker = f"{CRON_MARKER}{Path(app_dir).resolve()}"
    return [line for line in crontab.splitlines() if not line.rstrip().endswith(marker)]


def schedule(app_dir, frequency, local=False, extra=()):
    """Create (or replace) the scheduled check for a folder, or remove it with frequency "off".

    Returns {"folder", "frequency", "name", "command"}. Consent for hosted checks is the caller's job.
    """
    if frequency not in ("daily", "weekly", "off"):
        raise ScanError("Choose daily, weekly or off.")
    app_dir = Path(app_dir).resolve()
    if frequency == "off":
        return unschedule(app_dir)
    if not app_dir.is_dir():
        raise ScanError(f"{app_dir} is not a folder.")
    if os.name == "nt":
        command = windows_schedule(app_dir, frequency, local, extra)
        name = task_name(app_dir)
    else:
        line = cron_line(app_dir, frequency, local, extra, source_pythonpath())
        write_crontab(without_folder(read_crontab(), app_dir) + [line])
        command, name = line, f"crontab ({CRON_MARKER}{app_dir})"
    return {"folder": str(app_dir), "frequency": frequency, "name": name, "command": command}


def unschedule(app_dir):
    app_dir = Path(app_dir).resolve()
    if os.name == "nt":
        proc = run(["schtasks", "/Delete", "/F", "/TN", task_name(app_dir)])
        removed = proc.returncode == 0
        (APPLEDGER_HOME / "schedules" / f"{safe_name(app_dir)}.cmd").unlink(missing_ok=True)
    else:
        current = read_crontab()
        kept = without_folder(current, app_dir)
        removed = len(kept) != len(current.splitlines())
        if removed:
            write_crontab(kept)
    return {"folder": str(app_dir), "frequency": "off", "name": task_name(app_dir) if os.name == "nt" else None,
            "removed": removed}


FOLDER_IN_COMMAND = re.compile(r'-m appledger "([^"]+)"')


def describe(name, next_run, command):
    folder = FOLDER_IN_COMMAND.search(command)
    return {"name": name, "next_run": next_run, "folder": folder.group(1) if folder else None,
            "mode": "local" if " --local" in command else "hosted", "command": command}


def parse_task_query(csv_text):
    """AppLedger's tasks in `schtasks /Query /FO CSV /V`. That CSV doesn't escape the quotes in
    the command, and its column titles are localized, so lines are taken apart by hand."""
    found = {}
    for line in csv_text.splitlines():
        fields = line.split('","')
        if len(fields) < 4 or not fields[1].lstrip("\\").startswith(TASK_FOLDER + "\\"):
            continue
        name = fields[1].lstrip("\\")
        found[name] = describe(name, fields[2], line)
    return list(found.values())


def list_schedules():
    """Every scheduled AppLedger check on this computer: [{"name", "next_run", "folder", "mode", "command"}]."""
    if os.name == "nt":
        proc = run(["schtasks", "/Query", "/FO", "CSV", "/V"])
        return parse_task_query(proc.stdout) if proc.returncode == 0 else []
    tasks = []
    for line in read_crontab().splitlines():
        if CRON_MARKER in line:
            task = describe(line.split(CRON_MARKER, 1)[1], " ".join(line.split()[:5]), line)
            task["folder"] = task["name"]
            tasks.append(task)
    return tasks
