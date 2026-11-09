"""Unit and integration tests for backuper.scheduler (Windows Task Scheduler)."""

from __future__ import annotations

import csv
import io
import os
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import conftest
import pytest

from backuper import scheduler
from backuper.errors import ConfigError, PreflightError


# Allow the Windows-gated functions to run on the (Windows) test host while
# still exercising their real logic; non-Windows hosts skip the gated paths.
@pytest.fixture(autouse=True)
def _allow_windows(monkeypatch):
    monkeypatch.setattr(scheduler, "_require_windows", lambda: None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, results=None):
        self.calls = []
        self._results = list(results or [])

    def __call__(self, cmd, *args, **kwargs):
        self.calls.append((list(cmd), dict(kwargs)))
        if self._results:
            return self._results.pop(0)
        return FakeProc(0)


def _make_job(tmp_path, name="job"):
    job = tmp_path / name
    job.mkdir(exist_ok=True)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (job / "config.yaml").write_text(
        f"source: {src.as_posix()}\n", encoding="utf-8")
    return job, src


# ---------------------------------------------------------------------------
# task_name
# ---------------------------------------------------------------------------

def test_task_name_deterministic(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    assert scheduler.task_name(job, "diff") == scheduler.task_name(job, "diff")
    assert scheduler.task_name(job, "diff") != scheduler.task_name(job, "full")


def test_task_name_differs_by_path(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert scheduler.task_name(a, "diff") != scheduler.task_name(b, "diff")


def test_task_name_invalid_kind(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    with pytest.raises(ValueError):
        scheduler.task_name(job, "nope")


def test_task_name_slug_fallback(tmp_path):
    job = tmp_path / "!!!"
    job.mkdir()
    name = scheduler.task_name(job, "diff")
    assert name.startswith("backuper-job-diff-")


def test_task_name_slug_truncation(tmp_path):
    job = tmp_path / ("a" * 60)
    job.mkdir()
    name = scheduler.task_name(job, "diff")
    # slug portion is capped at 40 chars
    slug = name.split("-diff-")[0].removeprefix("backuper-")
    assert len(slug) <= 40


def test_task_name_has_digest_suffix(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    name = scheduler.task_name(job, "diff")
    assert name.count("-") >= 3
    assert len(name.rsplit("-", 1)[-1]) == 8


# ---------------------------------------------------------------------------
# parse_schedule
# ---------------------------------------------------------------------------

def test_parse_schedule_daily():
    spec = scheduler.parse_schedule("03:00", None, None, None)
    assert spec.daily == "03:00"
    assert spec.weekly_days == ()
    assert spec.at is None
    assert spec.interval_minutes is None


def test_parse_schedule_weekly():
    spec = scheduler.parse_schedule(None, "MON,WED", "09:30", None)
    assert spec.weekly_days == ("MON", "WED")
    assert spec.at == "09:30"


def test_parse_schedule_weekly_dedups():
    spec = scheduler.parse_schedule(None, "MON,MON,TUE", "09:30", None)
    assert spec.weekly_days == ("MON", "TUE")


def test_parse_schedule_interval():
    spec = scheduler.parse_schedule(None, None, None, 15)
    assert spec.interval_minutes == 15


def test_parse_schedule_none_provided():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, None, None)


def test_parse_schedule_multiple_provided():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule("03:00", None, None, 15)


def test_parse_schedule_daily_with_at():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule("03:00", None, "04:00", None)


def test_parse_schedule_weekly_without_at():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, "MON", None, None)


def test_parse_schedule_weekly_bad_day():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, "FOO", "09:00", None)


def test_parse_schedule_weekly_empty_token():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, "MON,", "09:00", None)


def test_parse_schedule_interval_with_at():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, "09:00", 15)


def test_parse_schedule_interval_bool():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, None, True)


def test_parse_schedule_interval_non_int():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, None, "15")


def test_parse_schedule_interval_bounds():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, None, 0)
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, None, None, 1440)


def test_parse_schedule_bad_time():
    with pytest.raises(ConfigError):
        scheduler.parse_schedule("24:00", None, None, None)
    with pytest.raises(ConfigError):
        scheduler.parse_schedule(None, "MON", "25:00", None)


def test_parse_time_strips():
    spec = scheduler.parse_schedule(" 03:00 ", None, None, None)
    assert spec.daily == "03:00"


# ---------------------------------------------------------------------------
# detect_backuper_command
# ---------------------------------------------------------------------------

def test_detect_default_source_checkout(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    program, prefix = scheduler.detect_backuper_command(None)
    assert program == sys.executable
    assert prefix == ["-m", "backuper"]


def test_detect_default_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    program, prefix = scheduler.detect_backuper_command(None)
    assert program == sys.executable
    assert prefix == []


def test_detect_exe_python(tmp_path):
    exe = tmp_path / "python.exe"
    exe.write_text("")
    program, prefix = scheduler.detect_backuper_command(str(exe))
    assert program == str(exe)
    assert prefix == ["-m", "backuper"]


def test_detect_exe_custom(tmp_path):
    exe = tmp_path / "backuper.exe"
    exe.write_text("")
    program, prefix = scheduler.detect_backuper_command(str(exe))
    assert program == str(exe)
    assert prefix == []


def test_detect_exe_missing(tmp_path):
    with pytest.raises(PreflightError):
        scheduler.detect_backuper_command(str(tmp_path / "nope.exe"))


# ---------------------------------------------------------------------------
# build_action
# ---------------------------------------------------------------------------

def test_build_action_basic(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    cmd, args, workdir = scheduler.build_action(job, "diff")
    assert cmd == "cmd.exe"
    job_abs = os.path.abspath(job)
    assert f'"{job_abs}"' in args
    assert "--scheduled" in args
    assert ">>" in args
    assert workdir == str(Path(scheduler.__file__).resolve().parent.parent)


def test_build_action_with_rar(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    rar = tmp_path / "Rar.exe"
    rar.write_text("")
    cmd, args, workdir = scheduler.build_action(job, "full", rar=str(rar))
    assert "--rar" in args
    assert f'"{str(rar)}"' in args
    assert "full" in args.split()


def test_build_action_invalid_kind(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    with pytest.raises(ValueError):
        scheduler.build_action(job, "nope")


def test_build_action_frozen_workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    job = tmp_path / "job"
    job.mkdir()
    cmd, args, workdir = scheduler.build_action(job, "diff")
    assert workdir == os.path.abspath(job)


def test_build_action_exe_python(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    exe = tmp_path / "python.exe"
    exe.write_text("")
    cmd, args, workdir = scheduler.build_action(job, "diff", exe=str(exe))
    assert f'"{str(exe)}"' in args
    assert "-m" in args and "backuper" in args


# ---------------------------------------------------------------------------
# build_task_xml
# ---------------------------------------------------------------------------

def test_build_task_xml_daily():
    spec = scheduler.ScheduleSpec(daily="03:00")
    xml = scheduler.build_task_xml(
        spec, "cmd.exe", "/d /c echo", "C:\\work",
        name="t", start_when_available=False, description="desc")
    assert xml.startswith(b"\xff\xfe")
    root = ET.fromstring(xml)
    ns = _NS
    trigger = root.find(f"{ns}Triggers/{ns}CalendarTrigger")
    assert trigger is not None
    assert trigger.findtext(f"{ns}StartBoundary") is not None
    assert trigger.find(f"{ns}ScheduleByDay") is not None
    assert trigger.findtext(f"{ns}ScheduleByDay/{ns}DaysInterval") == "1"
    assert root.findtext(f"{ns}RegistrationInfo/{ns}Description") == "desc"
    settings = root.find(f"{ns}Settings")
    assert settings.findtext(f"{ns}StartWhenAvailable") == "false"
    exec_el = root.find(f"{ns}Actions/{ns}Exec")
    assert exec_el.findtext(f"{ns}Command") == "cmd.exe"
    assert exec_el.findtext(f"{ns}Arguments") == "/d /c echo"
    assert exec_el.findtext(f"{ns}WorkingDirectory") == "C:\\work"


def test_build_task_xml_weekly():
    spec = scheduler.ScheduleSpec(weekly_days=("MON", "WED"), at="09:30")
    xml = scheduler.build_task_xml(spec, "cmd.exe", "args", "wd", name="t")
    root = ET.fromstring(xml)
    ns = _NS
    trigger = root.find(f"{ns}Triggers/{ns}CalendarTrigger")
    by_week = trigger.find(f"{ns}ScheduleByWeek")
    days = [e.tag.split("}")[1] for e in by_week.find(f"{ns}DaysOfWeek")]
    assert days == ["Monday", "Wednesday"]
    assert by_week.findtext(f"{ns}WeeksInterval") == "1"


def test_build_task_xml_interval():
    spec = scheduler.ScheduleSpec(interval_minutes=15)
    xml = scheduler.build_task_xml(spec, "cmd.exe", "args", "wd", name="t")
    root = ET.fromstring(xml)
    ns = _NS
    trigger = root.find(f"{ns}Triggers/{ns}TimeTrigger")
    assert trigger is not None
    assert trigger.findtext(f"{ns}Enabled") == "true"
    rep = trigger.find(f"{ns}Repetition")
    assert rep.findtext(f"{ns}Interval") == "PT15M"


def test_build_task_xml_uri():
    spec = scheduler.ScheduleSpec(daily="03:00")
    xml = scheduler.build_task_xml(spec, "cmd.exe", "args", "wd", name="my-task")
    root = ET.fromstring(xml)
    ns = _NS
    assert root.findtext(f"{ns}RegistrationInfo/{ns}URI") == "\\my-task"


# ---------------------------------------------------------------------------
# calendar / interval boundaries
# ---------------------------------------------------------------------------

class _FakeDateTime:
    @staticmethod
    def now():
        return datetime(2026, 1, 1, 10, 0, 0)


def test_calendar_boundary_future(monkeypatch):
    monkeypatch.setattr(scheduler, "datetime", _FakeDateTime)
    assert scheduler._calendar_boundary("11:00") == "2026-01-01T11:00:00"


def test_calendar_boundary_past_rolls(monkeypatch):
    monkeypatch.setattr(scheduler, "datetime", _FakeDateTime)
    assert scheduler._calendar_boundary("09:00") == "2026-01-02T09:00:00"


def test_interval_boundary(monkeypatch):
    monkeypatch.setattr(scheduler, "datetime", _FakeDateTime)
    # _interval_boundary uses scheduler.datetime? It calls datetime.now() via imported datetime.
    # Our _FakeDateTime only patches scheduler.datetime; _interval_boundary references datetime
    # name in module globals, so patch is enough.
    result = scheduler._interval_boundary()
    assert result == "2026-01-01T10:01:00"


# ---------------------------------------------------------------------------
# task_exists
# ---------------------------------------------------------------------------

def test_task_exists_true():
    runner = FakeRunner([FakeProc(0)])
    assert scheduler.task_exists("name", runner=runner) is True


def test_task_exists_false():
    runner = FakeRunner([FakeProc(1)])
    assert scheduler.task_exists("name", runner=runner) is False


# ---------------------------------------------------------------------------
# create_task
# ---------------------------------------------------------------------------

def test_create_task_missing_dir(tmp_path):
    runner = FakeRunner([])
    with pytest.raises(PreflightError):
        scheduler.create_task(tmp_path / "nope", "diff", scheduler.ScheduleSpec(daily="03:00"),
                             runner=runner)


def test_create_task_missing_config(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    runner = FakeRunner([])
    with pytest.raises(ConfigError):
        scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"), runner=runner)


def test_create_task_bad_kind(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([])
    with pytest.raises(ValueError):
        scheduler.create_task(job, "nope", scheduler.ScheduleSpec(daily="03:00"), runner=runner)


def test_create_task_missing_rar(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([])
    with pytest.raises(PreflightError):
        scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"),
                             rar=str(tmp_path / "nope.exe"), runner=runner)


def test_create_task_duplicate_without_force(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(0)])  # task_exists -> present
    with pytest.raises(PreflightError, match="already exists"):
        scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"), runner=runner)


def test_create_task_force_overwrites(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(0), FakeProc(0)])  # exists, then create ok
    name = scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"),
                                runner=runner, force=True)
    assert name == scheduler.task_name(job, "diff")
    create_call = runner.calls[-1][0]
    assert "/F" in create_call


def test_create_task_runner_failure(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(1), FakeProc(1, stderr="boom")])  # not exists, create fail
    with pytest.raises(PreflightError, match="schtasks failed"):
        scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"), runner=runner)


def test_create_task_success(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(1), FakeProc(0)])  # not exists, create ok
    name = scheduler.create_task(
        job, "diff", scheduler.ScheduleSpec(daily="03:00"),
        runner=runner, start_when_available=False)
    assert name == scheduler.task_name(job, "diff")
    assert runner.calls[0][0] == ["schtasks", "/Query", "/TN", name]
    create_call = runner.calls[1][0]
    assert create_call[:4] == ["schtasks", "/Create", "/TN", name]
    assert "/XML" in create_call
    xml_path = Path(create_call[create_call.index("/XML") + 1])
    assert not xml_path.exists()  # temp file cleaned up


def test_create_task_xml_passed_to_runner(tmp_path, monkeypatch):
    job, src = _make_job(tmp_path)
    captured = {}

    def runner(cmd, *a, **k):
        if "/XML" in cmd:
            p = Path(cmd[cmd.index("/XML") + 1])
            captured["xml"] = p.read_bytes()
        return FakeProc(0) if "/Create" in cmd else FakeProc(1)

    # task_exists first call returns not-found
    seq = {"n": 0}

    def seq_runner(cmd, *a, **k):
        seq["n"] += 1
        if seq["n"] == 1:
            return FakeProc(1)
        return runner(cmd, *a, **k)

    scheduler.create_task(job, "diff", scheduler.ScheduleSpec(daily="03:00"), runner=seq_runner)
    text = captured["xml"].decode("utf-16")
    assert "<Task" in text
    assert captured["xml"].startswith(b"\xff\xfe")


# ---------------------------------------------------------------------------
# delete_task
# ---------------------------------------------------------------------------

def test_delete_task_removed(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(0)])
    assert scheduler.delete_task(job, "diff", runner=runner) is True


def test_delete_task_absent(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(1), FakeProc(1)])  # delete fail, then not exists
    assert scheduler.delete_task(job, "diff", runner=runner) is False


def test_delete_task_failure(tmp_path):
    job, src = _make_job(tmp_path)
    runner = FakeRunner([FakeProc(1), FakeProc(0)])  # delete fail, but exists
    with pytest.raises(PreflightError):
        scheduler.delete_task(job, "diff", runner=runner)


# ---------------------------------------------------------------------------
# query_task / list_backuper_tasks
# ---------------------------------------------------------------------------

def test_query_task_found():
    runner = FakeRunner([FakeProc(0, stdout="details")])
    assert scheduler.query_task("name", runner=runner) == "details"


def test_query_task_not_found():
    runner = FakeRunner([FakeProc(1)])
    assert scheduler.query_task("name", runner=runner) is None


def test_list_backuper_tasks_parses_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["\\backuper-a-diff-1234", "x"])
    w.writerow(["\\OtherTask", "x"])
    w.writerow(["\\backuper-b-full-5678", "x"])
    runner = FakeRunner([FakeProc(0, stdout=buf.getvalue())])
    assert scheduler.list_backuper_tasks(runner=runner) == [
        "backuper-a-diff-1234", "backuper-b-full-5678"]


def test_list_backuper_tasks_failure():
    runner = FakeRunner([FakeProc(1)])
    assert scheduler.list_backuper_tasks(runner=runner) == []


def test_list_backuper_tasks_empty():
    runner = FakeRunner([FakeProc(0, stdout="")])
    assert scheduler.list_backuper_tasks(runner=runner) == []


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------

def test_run_injected_oserror():
    def runner(cmd, *a, **k):
        raise OSError("boom")

    with pytest.raises(PreflightError):
        scheduler._run(["/Query"], runner=runner)


def test_run_default_oserror(monkeypatch):
    def fake_run(*a, **k):
        raise OSError("boom")

    monkeypatch.setattr(scheduler.subprocess, "run", fake_run)
    with pytest.raises(PreflightError):
        scheduler._run(["/Query"])


# ---------------------------------------------------------------------------
# CLI wiring (monkeypatched scheduler)
# ---------------------------------------------------------------------------

def test_cli_schedule_add_success(job, capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "create_task", lambda *a, **k: "backuper-job-diff-123")
    assert conftest.run_cli(["schedule", "add", str(job.dir), "diff", "--daily", "03:00"]) == 0
    out = capsys.readouterr().out
    assert "created task backuper-job-diff-123" in out


def test_cli_schedule_add_config_error(job, capsys, monkeypatch):
    def raise_ce(*a, **k):
        raise ConfigError("bad config")

    monkeypatch.setattr(scheduler, "create_task", raise_ce)
    assert conftest.run_cli(["schedule", "add", str(job.dir), "diff", "--daily", "03:00"]) == 5
    assert "bad config" in capsys.readouterr().err


def test_cli_schedule_add_preflight_error(job, capsys, monkeypatch):
    def raise_pe(*a, **k):
        raise PreflightError("nope")

    monkeypatch.setattr(scheduler, "create_task", raise_pe)
    assert conftest.run_cli(["schedule", "add", str(job.dir), "diff", "--daily", "03:00"]) == 1
    assert "nope" in capsys.readouterr().err


def test_cli_schedule_remove(job, capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "delete_task", lambda *a, **k: True)
    assert conftest.run_cli(["schedule", "remove", str(job.dir)]) == 0
    assert "removed task" in capsys.readouterr().out


def test_cli_schedule_remove_not_found(job, capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "delete_task", lambda *a, **k: False)
    monkeypatch.setattr(scheduler, "task_name", lambda d, k: f"backuper-job-{k}-x")
    assert conftest.run_cli(["schedule", "remove", str(job.dir)]) == 0
    assert "not found" in capsys.readouterr().out


def test_cli_schedule_show_with_dir(job, capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "task_name", lambda d, k: "backuper-job-diff-x")
    monkeypatch.setattr(scheduler, "query_task", lambda name, runner=None: "DETAILS")
    assert conftest.run_cli(["schedule", "show", str(job.dir), "--kind", "diff"]) == 0
    out = capsys.readouterr().out
    assert "backuper-job-diff-x" in out
    assert "DETAILS" in out


def test_cli_schedule_show_without_dir(capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "list_backuper_tasks", lambda runner=None: ["backuper-x-diff-1"])
    monkeypatch.setattr(scheduler, "query_task", lambda name, runner=None: "DETAILS")
    assert conftest.run_cli(["schedule", "show"]) == 0
    out = capsys.readouterr().out
    assert "backuper-x-diff-1" in out
    assert "DETAILS" in out


def test_cli_schedule_show_empty(capsys, monkeypatch):
    monkeypatch.setattr(scheduler, "list_backuper_tasks", lambda runner=None: [])
    assert conftest.run_cli(["schedule", "show"]) == 0
    assert "no backuper tasks found" in capsys.readouterr().out


def test_cli_schedule_unknown_action(capsys):
    assert conftest.run_cli(["schedule"]) == 5
    assert "unknown schedule action" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Real integration (Windows only)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="requires Windows schtasks")
def test_real_schtasks_roundtrip(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    (job / "config.yaml").write_text(f"source: {src.as_posix()}\n", encoding="utf-8")

    name = None
    try:
        spec = scheduler.parse_schedule("03:00", None, None, None)
        name = scheduler.create_task(job, "diff", spec)
        assert scheduler.task_exists(name) is True

        text = scheduler.query_task(name)
        assert text is not None
        assert "cmd.exe" in text

        assert name in scheduler.list_backuper_tasks()
    finally:
        if name is not None:
            scheduler.delete_task(job, "diff")
            assert scheduler.task_exists(name) is False
