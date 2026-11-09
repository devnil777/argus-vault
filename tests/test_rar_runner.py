"""Tests of the rar_runner helpers.

Most tests are pure python and need no real Rar.exe; the stdin-password
end-to-end block at the bottom runs the real Rar.exe (skips with
reason "Rar.exe not found" when it is absent, like the other modules).
"""

from __future__ import annotations

import os
from pathlib import Path

import conftest
import pytest

from backuper import rar_runner


class FakeRunner:
    """Records the args of every run() call; never touches the filesystem."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def run(self, args, *, cwd=None, stdin_bytes=None, track_stdout=False,
            stdout_callback=None):
        self.calls.append(list(args))
        return rar_runner.RarResult(cmd=list(args), exit_code=0)


def test_create_step_pins_work_dir_to_archive_dir(tmp_path):
    target = tmp_path / "epoch" / "2026-01-01_000000_full.rar.tmp"
    target.parent.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    fake = FakeRunner()

    res = rar_runner.create_step(
        fake, target, source, ["a.txt"], final=True, compression=3)

    assert res.ok
    args = fake.calls[-1]
    workdir_arg = f"-w{os.path.abspath(target.parent)}"
    assert workdir_arg in args
    assert args.index(workdir_arg) == args.index(str(target)) - 1
    assert args[-1].startswith("@")


def test_create_step_non_final_still_pins_work_dir(tmp_path):
    target = tmp_path / "epoch" / "2026-01-01_000000_full.rar.tmp"
    target.parent.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    fake = FakeRunner()

    res = rar_runner.create_step(
        fake, target, source, ["a.txt"], final=False, compression=3)

    assert res.ok
    args = fake.calls[-1]
    assert f"-w{os.path.abspath(target.parent)}" in args
    assert "-qo+" not in args
    assert "-rr5" not in args


class ExtractFakeRunner:
    """Fake ``rar x``: writes every requested member under the destination."""

    def __init__(self, exit_code: int = 0):
        self.calls: list[list[str]] = []
        self.exit_code = exit_code

    def run(self, args, **kwargs):
        self.calls.append(list(args))
        if self.exit_code == 0:
            dest = Path(args[-1])
            for member in args[4:-1]:
                target = dest.joinpath(*member.split("\\"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(member.encode())
        return rar_runner.RarResult(cmd=list(args), exit_code=self.exit_code)


def test_read_service_members_uses_one_rar_x_call():
    fake = ExtractFakeRunner()
    archive = Path("archive.rar")
    members = [".backup/manifest.json", ".backup\\files.json"]

    out = rar_runner.read_service_members(fake, archive, members)

    assert len(fake.calls) == 1
    args = fake.calls[0]
    assert args[:3] == ["x", "-y", "-scfr"]
    assert args[3] == str(archive)
    assert args[-1].endswith(os.sep)
    member_args = args[4:-1]
    assert member_args == [".backup\\manifest.json", ".backup\\files.json"]
    assert all("/" not in m for m in member_args)
    assert out == {
        ".backup/manifest.json": b".backup\\manifest.json",
        ".backup\\files.json": b".backup\\files.json",
    }


def test_read_service_members_separator_spellings_equivalent():
    fake = ExtractFakeRunner()
    archive = Path("archive.rar")

    fwd = rar_runner.read_service_members(
        fake, archive, [".backup/manifest.json"])
    bs = rar_runner.read_service_members(
        fake, archive, [".backup\\manifest.json"])

    assert fwd[".backup/manifest.json"] == bs[".backup\\manifest.json"]
    assert fake.calls[0][4:-1] == [".backup\\manifest.json"]
    assert fake.calls[1][4:-1] == [".backup\\manifest.json"]


def test_read_service_members_empty_returns_empty():
    fake = ExtractFakeRunner()

    assert rar_runner.read_service_members(fake, Path("archive.rar"), []) == {}
    assert fake.calls == []


def test_read_service_member_delegates():
    fake = ExtractFakeRunner()

    data = rar_runner.read_service_member(
        fake, Path("archive.rar"), ".backup/manifest.json")

    assert len(fake.calls) == 1
    assert data == b".backup\\manifest.json"


def test_read_service_members_raises_on_nonzero_exit():
    fake = ExtractFakeRunner(exit_code=10)

    with pytest.raises(RuntimeError, match="10"):
        rar_runner.read_service_members(
            fake, Path("archive.rar"), [".backup/manifest.json"])


# ---------------------------------------------------------------------------
# Password transport: bare '-p' switch + stdin payload
# ---------------------------------------------------------------------------

class StdinFakeRunner:
    """Records args AND the stdin payload of every run() call."""

    def __init__(self, exit_code: int = 0):
        self.calls: list[dict] = []
        self.exit_code = exit_code

    def run(self, args, *, cwd=None, stdin_bytes=None, track_stdout=False,
            stdout_callback=None, timeout=None):
        self.calls.append(
            {"args": list(args), "cwd": cwd, "stdin_bytes": stdin_bytes})
        return rar_runner.RarResult(cmd=list(args), exit_code=self.exit_code)


def test_rar_password_stdin_helper_contract():
    assert rar_runner._rar_password_stdin(None) == ([], None)
    assert rar_runner._rar_password_stdin(b"s3cret") == (["-p"], b"s3cret\r\n")
    with pytest.raises(TypeError):
        rar_runner._rar_password_stdin("s3cret")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        rar_runner._rar_password_stdin(b"")


def test_create_step_password_travels_only_via_stdin(tmp_path):
    target = tmp_path / "epoch" / "2026-01-01_000000_full.rar.tmp"
    target.parent.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    fake = StdinFakeRunner()
    secret = "s3cret-pass"

    res = rar_runner.create_step(
        fake, target, source, ["a.txt"], final=True, compression=3,
        password=secret.encode())

    assert res.ok
    call = fake.calls[-1]
    # The whole payload is exactly password + CRLF.
    assert call["stdin_bytes"] == b"s3cret-pass\r\n"
    args = call["args"]
    # Bare '-p' switch present, exactly once, never attached to a secret.
    assert args.count("-p") == 1
    assert not any(a.startswith("-p") and a != "-p" for a in args)
    assert all(secret not in a for a in args)
    # RarResult.cmd (what loggers format) must carry no secret either.
    assert all(secret not in a for a in res.cmd)


def test_create_step_without_password_keeps_legacy_stdin(tmp_path):
    target = tmp_path / "epoch" / "2026-01-01_000000_full.rar.tmp"
    target.parent.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    fake = StdinFakeRunner()

    res = rar_runner.create_step(
        fake, target, source, ["a.txt"], final=False, compression=3)

    assert res.ok
    call = fake.calls[-1]
    assert "-p" not in call["args"]
    assert call["stdin_bytes"] is None


def test_test_archive_password_via_bare_p_switch():
    fake = StdinFakeRunner()

    code = rar_runner.test_archive(fake, Path("a.rar"), password=b"pw")

    assert code == 0
    call = fake.calls[-1]
    assert call["args"][:4] == ["t", "-scfr", "-p", "a.rar"]
    assert call["stdin_bytes"] == b"pw\r\n"


def test_test_archive_without_password_unchanged():
    fake = StdinFakeRunner()

    code = rar_runner.test_archive(fake, Path("a.rar"))

    assert code == 0
    call = fake.calls[-1]
    assert call["args"] == ["t", "-scfr", "a.rar"]
    assert call["stdin_bytes"] is None


def test_list_entries_password_via_bare_p_switch():
    fake = StdinFakeRunner()

    entries = rar_runner.list_entries(fake, Path("e.rar"), password=b"pw")

    assert entries == []  # exit 0, empty stdout parses to no items
    call = fake.calls[-1]
    # lt, -scfr, -p, <archive> — the switch sits before the archive name.
    assert call["args"] == ["lt", "-scfr", "-p", "e.rar"]
    assert call["stdin_bytes"] == b"pw\r\n"


def test_redact_strips_password_from_argv_form():
    secret = b"S3cret"
    # The forbidden '-p<secret>' argv form degrades to '-p<redacted>'.
    assert rar_runner.redact(["rar.exe", "a", "-pS3cret", "x.rar"], secret) \
        == ["rar.exe", "a", "-p<redacted>", "x.rar"]
    # A secret embedded anywhere else is stripped too.
    assert rar_runner.redact(["password=S3cret!"], secret + b"!") \
        == ["password=<redacted>"]
    # Bare '-p' (stdin mode) contains no secret and passes through.
    assert rar_runner.redact(["a", "-p", "x.rar"], secret) \
        == ["a", "-p", "x.rar"]
    # No password: an unchanged copy, not the caller's list.
    args = ["a", "-y"]
    out = rar_runner.redact(args, None)
    assert out == args and out is not args


# ---------------------------------------------------------------------------
# End-to-end with the real Rar.exe (skips without Rar.exe)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")
def test_stdin_password_e2e(rar, tmp_path):
    """Create with a stdin password; then test/list/extract with and without.

    Verified contract for RAR 7.22: one prompt on `a`, none on `lt`, a
    wrong password on t/x exits 11 without hanging, and with plain '-p'
    encryption the headers stay open (lt works WITHOUT a password).
    """
    src = tmp_path / "src"
    src.mkdir()
    payload = b"hello encrypted\n"
    (src / "small.txt").write_bytes(payload)
    target = tmp_path / "enc.rar"
    password = f"e2e-pass-{os.urandom(4).hex()}".encode()

    res = rar_runner.create_step(
        rar, target, src, ["small.txt"], final=True, compression=3,
        password=password)
    assert res.ok, res.exit_description
    # The secret never appears in the recorded command line.
    assert "-p" in res.cmd
    assert password.decode("utf-8", errors="ignore") not in " ".join(res.cmd)

    # Headers are open: listing succeeds WITHOUT a password (no prompt).
    entries = rar_runner.list_entries(rar, target)
    names = [e["Name"] for e in entries]
    assert names == ["small.txt"]

    # Listing with the password also works and is identical.
    assert [e["Name"] for e in
            rar_runner.list_entries(rar, target, password=password)] == names

    # Integrity test with the right password: exit 0, no prompt, no hang.
    assert rar_runner.test_archive(rar, target, password=password) == 0

    # A WRONG password never hangs: RAR reports exit 11 ("wrong password").
    assert rar_runner.test_archive(rar, target, password=password + b"-alt") == 11

    # Encrypted DATA is unreadable without the password (data-level check
    # via x + password succeeds; without one RAR would hang on its prompt,
    # so only the password path is asserted here).
    got = rar_runner.read_service_members(
        rar, target, ["small.txt"], password=password)
    assert got == {"small.txt": payload}


RU_LT_SAMPLE = '''

RAR 7.22 x64    Авторские права (c) 1993-2026 Александр Рошал    1 май 2026
Пробная версия     ('RAR -?' - справка)

Архив: C:\\tmp\\a.rar
Детали: RAR 5

         Имя: Users\\tmp\\src\\a.txt
         Тип: Файл
      Размер: 5
    В архиве: 5
      Сжатие: 100%
     Изменён: 2026-11-09 12:46:25,493373000
    Атрибуты: ..A....
       CRC32: 3610A686
  Базовая ОС: Windows
   Архивация: RAR 5.0(v50) -m0 -md=128k

         Имя: Users\\tmp\\src\\empty
         Тип: Каталог
     Изменён: 2026-11-09 12:46:25,494373400
    Атрибуты: ...D...
  Базовая ОС: Windows
   Архивация: RAR 5.0(v50) -m0

      Сервис: EOF
'''


def test_parse_lt_russian_canonicalizes_labels_and_types():
    entries = rar_runner.parse_lt(rar_runner.strip_rar_banner(RU_LT_SAMPLE))
    assert len(entries) == 2
    assert entries[0]["Name"].endswith("a.txt")
    assert entries[0]["Type"] == "File"
    assert entries[0]["Size"] == "5"
    assert entries[0]["Modified"].startswith("2026-11-09")
    assert entries[1]["Type"] == "Folder"


def test_strip_rar_banner_russian_removes_banner():
    out = rar_runner.strip_rar_banner(RU_LT_SAMPLE)
    assert "Имя" in out
    assert "Авторские права" not in out


def test_warning_lines_russian():
    raw = ("Невозможно открыть x.txt\nНе удается найти указанный файл.\n"
           "Обнаружен повреждённый заголовок\nОШИБКА\n").encode()
    r = rar_runner.RarResult(cmd=[], exit_code=3, stdout_raw=raw, stderr_raw=b"",
                             stdout_chunks=[])
    wl = r.warning_lines()
    assert any("Невозможно" in w for w in wl)
    assert any("ОШИБ" in w for w in wl)


def test_detect_rar_language_russian_and_english():
    class FakeRunner:
        def __init__(self, text):
            self.text = text

        def run(self, args, **kw):
            return rar_runner.RarResult(cmd=args, exit_code=0,
                                       stdout_raw=self.text.encode("utf-8"),
                                       stderr_raw=b"", stdout_chunks=[])

    ru = FakeRunner("RAR 7.22 x64    Авторские права (c) 2026\nПробная версия  ('RAR -?' - справка)\n")
    en = FakeRunner("RAR 7.22 x64    Copyright (c) 2026\nTrial version  Type 'rar -?' for help\n")
    assert rar_runner.detect_rar_language(ru) == "ru"
    assert rar_runner.detect_rar_language(en) == "en"
    assert rar_runner.detect_rar_language(FakeRunner("RAR 7.22 x64\n")) == "unknown"
