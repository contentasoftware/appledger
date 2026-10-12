"""Scheduled checks: the commands handed to Task Scheduler and cron (no real task is created)."""

import os
from pathlib import Path
from unittest import mock

from helpers import new_dir, run_all

from appledger import schedule

PY = r"C:\Program Files\Python313\python.exe"


def test_task_name_is_safe_and_unique():
    a, b = new_dir("one") / "My App (v2)", new_dir("two") / "My App (v2)"
    a.mkdir()
    b.mkdir()
    name = schedule.task_name(a)
    assert name.startswith("AppLedger\\My-App-v2-") and len(name.split("\\")[1]) == len("My-App-v2-") + 6
    assert schedule.task_name(a) != schedule.task_name(b)


def test_windows_command_installed_package():
    app = new_dir("app")
    cmd = schedule.windows_command(app, python=PY)
    assert cmd == f'"{PY}" -m appledger "{app.resolve()}" --yes --quiet', cmd
    cmd = schedule.windows_command(app, local=True, extra=["--no-dashboard", "--app-name", 'Sales "quote" tool'],
                                   python=PY)
    assert cmd.endswith('--yes --quiet --local --no-dashboard --app-name "Sales quote tool"'), cmd


def test_windows_command_from_source_checkout_sets_pythonpath():
    app = new_dir("app")
    cmd = schedule.windows_command(app, pythonpath=r"D:\src", python=PY)
    assert cmd == f'cmd /c "set PYTHONPATH=D:\\src&& "{PY}" -m appledger "{app.resolve()}" --yes --quiet"', cmd


def test_source_pythonpath_detects_checkout():
    # These tests import appledger from src/, so the scheduled task needs PYTHONPATH.
    assert Path(schedule.source_pythonpath()) == Path(__file__).resolve().parent.parent / "src"


def test_windows_schtasks_arguments():
    app = new_dir("app")
    with mock.patch.object(schedule, "run") as run, mock.patch.object(os, "name", "nt"), \
            mock.patch.object(schedule, "source_pythonpath", return_value=None):
        run.return_value.returncode = 0
        done = schedule.schedule(app, "weekly", local=True)
    args = run.call_args[0][0]
    assert args[:8] == ["schtasks", "/Create", "/F", "/SC", "WEEKLY", "/ST", "09:00", "/TN"], args
    assert args[8] == schedule.task_name(app) and args[9] == "/TR"
    assert args[10].endswith(f'-m appledger "{app.resolve()}" --yes --quiet --local')
    assert done["frequency"] == "weekly"


def test_long_windows_command_uses_wrapper_script():
    app = new_dir("a" * 120)
    with mock.patch.object(schedule, "run") as run, mock.patch.object(os, "name", "nt"), \
            mock.patch.object(schedule, "source_pythonpath", return_value="D:\\" + "s" * 120):
        run.return_value.returncode = 0
        schedule.schedule(app, "daily")
    tr = run.call_args[0][0][-1]
    assert tr.endswith('.cmd"') and len(tr) <= schedule.MAX_TASK_COMMAND
    script = Path(tr.strip('"')).read_text(encoding="utf-8")
    assert "set PYTHONPATH=" in script and "--yes --quiet" in script


def test_off_deletes_task():
    app = new_dir("app")
    with mock.patch.object(schedule, "run") as run, mock.patch.object(os, "name", "nt"):
        run.return_value.returncode = 0
        done = schedule.schedule(app, "off")
    assert run.call_args[0][0] == ["schtasks", "/Delete", "/F", "/TN", schedule.task_name(app)]
    assert done["removed"] is True


def test_cron_line():
    app = new_dir("my app")
    line = schedule.cron_line(app, "daily", pythonpath="/home/me/src", python="/usr/bin/python3")
    assert line.startswith("0 9 * * * PYTHONPATH=/home/me/src /usr/bin/python3 -m appledger "), line
    assert "--yes --quiet" in line and line.endswith(f"# appledger:{app.resolve()}")
    assert schedule.cron_line(app, "weekly", local=True, python="py").startswith("0 9 * * 1 py -m appledger")
    assert "--local" in schedule.cron_line(app, "weekly", local=True, python="py")


def test_cron_replace_keeps_other_lines():
    app = new_dir("app")
    other = "*/5 * * * * backup.sh"
    old = schedule.cron_line(app, "weekly", python="py")
    assert schedule.without_folder(f"{other}\n{old}\n", app) == [other]


def test_parse_task_query():
    # Real schtasks output: the quotes inside the command are not escaped in the CSV field.
    csv_text = (
        '"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author",'
        '"Task To Run","Start In"\n'
        '"PC","\\AppLedger\\shop-abc123","10/13/2026 9:00:00 AM","Ready","Interactive only","N/A","1","me",'
        '"cmd /c "set PYTHONPATH=D:\\src&& "C:\\py\\python.exe" -m appledger "D:\\my shop" --yes --quiet --local"",'
        '"N/A"\n'
        '"PC","\\Microsoft\\Other","N/A","Ready","Interactive","N/A","1","me","x.exe","N/A"\n'
    )
    tasks = schedule.parse_task_query(csv_text)
    assert [t["name"] for t in tasks] == ["AppLedger\\shop-abc123"], tasks
    assert tasks[0]["next_run"] == "10/13/2026 9:00:00 AM"
    assert tasks[0]["folder"] == "D:\\my shop" and tasks[0]["mode"] == "local"


if __name__ == "__main__":
    run_all(dict(globals()))
