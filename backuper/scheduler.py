"""Windows Task Scheduler integration via ``schtasks.exe``.

Schedules are described by :class:`ScheduleSpec` and translated to a Task
Scheduler XML document. Each registered task is named deterministically from
the job directory and the run kind, so repeated calls target the same task
and different job paths never collide::

    backuper-<slug>-<diff|full>-<sha256-prefix>

The slug comes from the job directory name, while the digest covers the
normalized absolute path. Tasks run the same ``backuper`` entry point the CLI
uses (``python -m backuper`` unless a frozen executable is detected) and are
wrapped in ``cmd.exe /d /c`` so the job's ``.schedule.log`` receives merged
stdout/stderr. Exit codes from scheduled runs therefore remain the normal
backuper codes; failures while *managing* a task are normalized to
:class:`PreflightError` (exit code 1) or :class:`ConfigError` (exit code 5).

All schtasks invocations go through :func:`_run`, which accepts an injectable
runner for testing. Functions only require Windows at call time, never at
import time, so the module stays importable and unit-testable elsewhere.
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from backuper.config import CONFIG_NAME, load_config
from backuper.errors import ConfigError, PreflightError

KINDS = ("diff", "full")

_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"

_WEEKDAY_NAMES = {
    "MON": "Monday",
    "TUE": "Tuesday",
    "WED": "Wednesday",
    "THU": "Thursday",
    "FRI": "Friday",
    "SAT": "Saturday",
    "SUN": "Sunday",
}

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")

Runner = Callable[..., Any]


@dataclass(frozen=True)
class ScheduleSpec:
    """A validated schedule: exactly one of daily, weekly or interval is set."""

    daily: str | None = None
    weekly_days: tuple[str, ...] = ()
    at: str | None = None
    interval_minutes: int | None = None


def _require_windows() -> None:
    """Reject task management outside Windows."""
    if os.name != "nt":
        raise PreflightError(
            "task scheduling requires Windows and schtasks.exe; this platform is not supported")


def task_name(job_dir: Path, kind: str) -> str:
    """Return the deterministic task name for a job directory and run kind."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}")
    raw = Path(job_dir).name
    slug = _SLUG_RE.sub("_", raw).strip("._-")[:40] or "job"
    key = os.path.normcase(os.path.abspath(job_dir)).encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:8]
    return f"backuper-{slug}-{kind}-{digest}"


def _parse_time(value: str, option: str) -> str:
    """Validate an ``HH:MM`` value and return it stripped."""
    text = value.strip()
    if not _TIME_RE.match(text):
        raise ConfigError(f"{option} must be a time in HH:MM form (00:00..23:59), got {value!r}")
    return text


def parse_schedule(
    daily: str | None,
    weekly: str | None,
    at: str | None,
    interval: int | None,
) -> ScheduleSpec:
    """Validate CLI schedule options and build a :class:`ScheduleSpec`."""
    provided = [
        flag
        for flag, value in (("daily", daily), ("weekly", weekly), ("interval", interval))
        if value is not None
    ]
    if len(provided) != 1:
        raise ConfigError(
            "specify exactly one schedule: --daily HH:MM, --weekly DAYS --at HH:MM, "
            "or --interval MINUTES")

    if daily is not None:
        if at is not None:
            raise ConfigError("--at cannot be combined with --daily")
        return ScheduleSpec(daily=_parse_time(daily, "--daily"))

    if weekly is not None:
        if at is None:
            raise ConfigError("--weekly requires --at HH:MM")
        tokens = [token.strip().upper() for token in weekly.split(",")]
        if not tokens or any(not token for token in tokens):
            raise ConfigError(
                "--weekly must be a comma-separated list of day names: "
                "MON,TUE,WED,THU,FRI,SAT,SUN")
        invalid = [token for token in tokens if token not in _WEEKDAY_NAMES]
        if invalid:
            raise ConfigError(
                f"--weekly contains invalid day name(s): {', '.join(invalid)}; "
                "allowed values are MON,TUE,WED,THU,FRI,SAT,SUN")
        days = tuple(dict.fromkeys(tokens))
        return ScheduleSpec(weekly_days=days, at=_parse_time(at, "--at"))

    if at is not None:
        raise ConfigError("--at cannot be combined with --interval")
    if isinstance(interval, bool) or not isinstance(interval, int):
        raise ConfigError(f"--interval must be an integer number of minutes, got {interval!r}")
    if not 1 <= interval <= 1439:
        raise ConfigError(f"--interval must be between 1 and 1439 minutes, got {interval}")
    return ScheduleSpec(interval_minutes=interval)


def detect_backuper_command(exe: str | None) -> tuple[str, list[str]]:
    """Return the program and prefix arguments used to invoke backuper."""
    if exe is not None:
        path = Path(exe)
        if not path.is_file():
            raise PreflightError(f"backuper executable not found: {exe}")
        program = str(path)
        prefix = ["-m", "backuper"] if path.name.lower().startswith("python") else []
        return program, prefix
    if getattr(sys, "frozen", False):
        return sys.executable, []
    return sys.executable, ["-m", "backuper"]


def build_action(
    job_dir: Path,
    kind: str,
    *,
    exe: str | None = None,
    rar: str | None = None,
    signing_private_key: str | None = None,
) -> tuple[str, str, str]:
    """Build the scheduled command line, returning (command, arguments, workdir)."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}")
    job_abs = os.path.abspath(job_dir)
    log = os.path.join(job_abs, ".schedule.log")
    program, prefix = detect_backuper_command(exe)

    pieces = [f'"{program}"', *prefix, kind, f'"{job_abs}"']
    if rar is not None:
        pieces.extend(["--rar", f'"{rar}"'])
    if signing_private_key is not None:
        pieces.extend(["--signing-private-key", f'"{signing_private_key}"'])
    pieces.extend(["--scheduled", f'>> "{log}" 2>&1'])

    # A source checkout runs as ``python -m backuper``, which requires the
    # package parent on sys.path; its own directory is not the job dir.
    workdir = job_abs
    if exe is None and not getattr(sys, "frozen", False):
        workdir = str(Path(__file__).resolve().parent.parent)

    cmdline = " ".join(pieces)
    return "cmd.exe", f'/d /c "{cmdline}"', workdir


def _q(tag: str) -> str:
    """Return a tag qualified with the Task Scheduler namespace."""
    return f"{{{_NS}}}{tag}"


def _current_user() -> str:
    """Return the current user as ``DOMAIN\\user`` when possible."""
    domain = os.environ.get("USERDOMAIN", "").strip()
    username = os.environ.get("USERNAME", "").strip()
    if domain and username:
        return f"{domain}\\{username}"
    return getpass.getuser()


def _schedule_description(schedule: ScheduleSpec) -> str:
    if schedule.daily is not None:
        return f"daily at {schedule.daily}"
    if schedule.weekly_days:
        return f"weekly on {', '.join(schedule.weekly_days)} at {schedule.at}"
    if schedule.interval_minutes is not None:
        return f"every {schedule.interval_minutes} minutes"
    return "unscheduled"


def _calendar_boundary(at: str) -> str:
    """Return a local start boundary, rolled to tomorrow when it is already past."""
    now = datetime.now()
    hour, minute = (int(part) for part in at.split(":"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate.strftime("%Y-%m-%dT%H:%M:%S")


def _interval_boundary() -> str:
    """Return a local start boundary rounded up to the next whole minute."""
    moment = datetime.now().replace(second=0, microsecond=0) + timedelta(minutes=1)
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


def _add(parent: ET.Element, tag: str, text: str) -> ET.Element:
    element = ET.SubElement(parent, _q(tag))
    element.text = text
    return element


def build_task_xml(
    schedule: ScheduleSpec,
    command: str,
    arguments: str,
    working_directory: str,
    *,
    name: str,
    start_when_available: bool = True,
    description: str | None = None,
) -> bytes:
    """Serialize a Task Scheduler XML document for ``schedule`` as UTF-16 bytes."""
    ET.register_namespace("", _NS)
    root = ET.Element(_q("Task"), {"version": "1.2"})

    registration = ET.SubElement(root, _q("RegistrationInfo"))
    _add(registration, "Date", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S"))
    _add(registration, "Author", _current_user())
    _add(registration, "Description",
         description if description is not None else f"backuper {_schedule_description(schedule)}")
    _add(registration, "URI", "\\" + name)

    triggers = ET.SubElement(root, _q("Triggers"))
    if schedule.interval_minutes is not None:
        trigger = ET.SubElement(triggers, _q("TimeTrigger"))
        _add(trigger, "StartBoundary", _interval_boundary())
        _add(trigger, "Enabled", "true")
        repetition = ET.SubElement(trigger, _q("Repetition"))
        _add(repetition, "Interval", f"PT{schedule.interval_minutes}M")
        _add(repetition, "StopAtDurationEnd", "false")
    else:
        trigger = ET.SubElement(triggers, _q("CalendarTrigger"))
        _add(trigger, "StartBoundary", _calendar_boundary(schedule.daily or schedule.at or "00:00"))
        _add(trigger, "Enabled", "true")
        if schedule.daily is not None:
            by_day = ET.SubElement(trigger, _q("ScheduleByDay"))
            _add(by_day, "DaysInterval", "1")
        else:
            by_week = ET.SubElement(trigger, _q("ScheduleByWeek"))
            days_of_week = ET.SubElement(by_week, _q("DaysOfWeek"))
            for day in schedule.weekly_days:
                ET.SubElement(days_of_week, _q(_WEEKDAY_NAMES[day]))
            _add(by_week, "WeeksInterval", "1")

    principals = ET.SubElement(root, _q("Principals"))
    principal = ET.SubElement(principals, _q("Principal"), {"id": "Author"})
    _add(principal, "UserId", _current_user())
    _add(principal, "LogonType", "InteractiveToken")
    _add(principal, "RunLevel", "LeastPrivilege")

    settings = ET.SubElement(root, _q("Settings"))
    _add(settings, "MultipleInstancesPolicy", "IgnoreNew")
    _add(settings, "DisallowStartIfOnBatteries", "false")
    _add(settings, "StopIfGoingOnBatteries", "false")
    _add(settings, "AllowHardTerminate", "true")
    _add(settings, "StartWhenAvailable", "true" if start_when_available else "false")
    _add(settings, "RunOnlyIfNetworkAvailable", "false")
    idle = ET.SubElement(settings, _q("IdleSettings"))
    _add(idle, "StopOnIdleEnd", "false")
    _add(idle, "RestartOnIdle", "false")
    _add(settings, "AllowStartOnDemand", "true")
    _add(settings, "Enabled", "true")
    _add(settings, "Hidden", "false")
    _add(settings, "RunOnlyIfIdle", "false")
    _add(settings, "WakeToRun", "false")
    _add(settings, "ExecutionTimeLimit", "PT0S")
    _add(settings, "Priority", "7")

    actions = ET.SubElement(root, _q("Actions"), {"Context": "Author"})
    exec_action = ET.SubElement(actions, _q("Exec"))
    _add(exec_action, "Command", command)
    _add(exec_action, "Arguments", arguments)
    _add(exec_action, "WorkingDirectory", working_directory)

    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def _console_encoding() -> str:
    """Best-effort encoding used by ``schtasks`` on this machine.

    ``schtasks`` writes its output in the console's OEM code page (866 on a
    typical Russian Windows install), not in the process locale encoding that
    ``subprocess`` would otherwise assume.  Resolving the code page keeps the
    output decodable; ``errors="replace"`` in :func:`_run` is the safety net.
    """
    if os.name == "nt":
        try:
            import ctypes

            codepage = ctypes.windll.kernel32.GetConsoleOutputCP()
            if codepage:
                return f"cp{codepage}"
        except (AttributeError, OSError, ValueError):
            pass
    return "utf-8"


def _run(args: list[str], runner: Runner | None = None) -> Any:
    """Run ``schtasks`` with the given arguments, normalizing spawn failures."""
    try:
        if runner is None:
            return subprocess.run(
                ["schtasks", *args],
                capture_output=True,
                text=True,
                encoding=_console_encoding(),
                errors="replace",
                check=False,
            )
        return runner(["schtasks", *args], capture_output=True, text=True, check=False)
    except OSError as exc:
        raise PreflightError(f"cannot run schtasks: {exc}") from exc


def _error_text(proc: Any) -> str:
    """Combine schtasks stderr/stdout into a useful error message."""
    parts = [
        str(getattr(proc, "stderr", "") or "").strip(),
        str(getattr(proc, "stdout", "") or "").strip(),
    ]
    text = "\n".join(part for part in parts if part)
    if text:
        return text
    return f"schtasks exited with code {getattr(proc, 'returncode', '?')}"


def task_exists(name: str, *, runner: Runner | None = None) -> bool:
    """Return True when a task with ``name`` is registered."""
    proc = _run(["/Query", "/TN", name], runner)
    return proc.returncode == 0


def create_task(
    job_dir: Path,
    kind: str,
    schedule: ScheduleSpec,
    *,
    exe: str | None = None,
    rar: str | None = None,
    signing_private_key: str | None = None,
    force: bool = False,
    start_when_available: bool = True,
    runner: Runner | None = None,
) -> str:
    """Register or replace a scheduled task; return its name."""
    _require_windows()
    job_dir = Path(job_dir)
    if not job_dir.is_dir():
        raise PreflightError(f"job directory not found: {job_dir}")
    config_path = job_dir / CONFIG_NAME
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")
    load_config(config_path)
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}")
    if rar is not None and not Path(rar).is_file():
        raise PreflightError(f"Rar.exe not found: {rar}")

    name = task_name(job_dir, kind)
    if not force and task_exists(name, runner=runner):
        raise PreflightError(
            f"task {name!r} already exists; pass --force to replace it")

    command, arguments, working_directory = build_action(
        job_dir, kind, exe=exe, rar=rar, signing_private_key=signing_private_key)
    xml = build_task_xml(
        schedule,
        command,
        arguments,
        working_directory,
        name=name,
        start_when_available=start_when_available,
    )

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            tmp.write(xml)
            tmp_path = Path(tmp.name)
        args = ["/Create", "/TN", name, "/XML", str(tmp_path)]
        if force:
            args.append("/F")
        proc = _run(args, runner)
        if proc.returncode != 0:
            raise PreflightError(
                f"schtasks failed to create task {name!r}: {_error_text(proc)}")
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass
    return name


def delete_task(job_dir: Path, kind: str, *, runner: Runner | None = None) -> bool:
    """Delete the job's task; return True when removed, False when absent."""
    _require_windows()
    name = task_name(job_dir, kind)
    proc = _run(["/Delete", "/TN", name, "/F"], runner)
    if proc.returncode == 0:
        return True
    if not task_exists(name, runner=runner):
        return False
    raise PreflightError(f"schtasks failed to delete task {name!r}: {_error_text(proc)}")


def query_task(name: str, *, runner: Runner | None = None) -> str | None:
    """Return verbose task details, or None when the task does not exist."""
    _require_windows()
    proc = _run(["/Query", "/TN", name, "/FO", "LIST", "/V"], runner)
    if proc.returncode == 0:
        return proc.stdout
    return None


def list_backuper_tasks(*, runner: Runner | None = None) -> list[str]:
    """Return sorted names of all registered ``backuper-`` tasks."""
    _require_windows()
    proc = _run(["/Query", "/FO", "CSV", "/NH"], runner)
    if proc.returncode != 0:
        return []
    names: set[str] = set()
    for row in csv.reader(io.StringIO(proc.stdout or "")):
        if not row:
            continue
        name = row[0].strip()
        if name.startswith("\\"):
            name = name[1:]
        if name.startswith("backuper-"):
            names.add(name)
    return sorted(names)
