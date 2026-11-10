"""Isolated layer for invoking the RAR archiver.

This is the ONLY module in the project allowed to know RAR command-line
details: everything else talks to RAR exclusively through RarRunner and
the helpers below, so swapping the archiver later means reimplementing
this module only.

Canonical invocation forms (validated empirically against Rar.exe 7.22,
see DIAGNOSTICS.md; the TRIAL build prints a two-line banner before every
output — strip_rar_banner removes it):

    Rar.exe a -y -scflr -os -r- -m<N> [-qo+ -rr5] -w<archive dir> <target> @<listfile>
        create step (create_step). Listfile: UTF-8 (no BOM), CRLF,
        relative names with backslashes, dirs WITHOUT trailing separator
        ('dir\\' is silently ignored by RAR).
        -w<archive dir>: RAR's archive-modification work file
        (__rar_<pid>.<tid>.rartemp) must NOT land in the process cwd —
        during the content step the cwd is the SOURCE ROOT (DIAGNOSTICS #15).
    Rar.exe lt|lb|lta -scfr <archive>
        technical / bare / service-inclusive listing (UTF-8 output).
    Rar.exe t <archive>
        integrity test; exit 3 = CRC damage.
    Rar.exe r -y <archive>          (must run with cwd = archive parent)
        repair via the recovery record. RAR writes 'fixed.<basename>'
        into the PROCESS CWD — not next to the archive (probed
        empirically; DIAGNOSTICS #13 only saw it "next to" because its
        check ran with cwd == archive parent). repair() pins the cwd.
    Rar.exe x -y -scfr <archive> <dest>\\
        extract everything.
    Rar.exe x -y -scfr <archive> <member\\with\\backslashes> ... <dest>\\
        extract stored members (read_service_members). The member names
        need BACKSLASHES (forward slashes -> exit 10 "no files found")
        and the destination must be a plain path (a \\\\?\\-prefixed dest
        fails with exit 9).

Password transport (verified empirically against Rar.exe 7.22): the
archive password NEVER travels on the command line — a '-p<secret>'
switch would leak into process lists and Rar.exe's own activity log.
Every password-bearing call instead carries the bare '-p' switch and
writes the password + CRLF to RAR's stdin:

    Rar.exe a ... -p <target> @<listfile>          stdin: pw CRLF
    Rar.exe t|lt|lb|lta ... -p <archive>           stdin: pw CRLF

Contract: on `a` RAR prints exactly ONE prompt ("Enter password (will
not be echoed): ", no file name) and accepts ONE line — CRLF line end
is fine, no confirmation re-enter — then encrypts every newly added
entry; a second `a` into the same archive behaves the same. On lt/t no
prompt is issued and nothing is consumed from stdin (feeding the line
anyway is harmless and fully prevents any interactive prompt). Headers
stay open: `lt` lists a plain '-p'-encrypted archive fine WITHOUT a
password. A WRONG password fed to t/x never hangs: RAR exits 11
("wrong password"). Encoding must go through _rar_password_stdin();
should any future code switch back to an argv password form, every
args-list formatting site must route the list through redact() first
(RarResult.cmd is echoed verbatim, e.g. in the archiver error report).

Timeout policy: run() defaults to UNLIMITED — 10 GB+ archives run long
and a hung RAR is better stopped by the user (Ctrl+C) than killed by an
arbitrary limit. On an explicit timeout expiry the process is killed and
exit_code is -1 (internal sentinel; 255 stays reserved for RAR's real
"user stopped the process"). Tiny operations (version probe, listing)
pass explicit short timeouts.
"""

from __future__ import annotations

import codecs
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

# Exit codes of console RAR (see Rar.txt, "Exit values").
RAR_EXIT_DESCRIPTIONS = {
    0: "successful operation",
    1: "non-fatal error(s) occurred",
    2: "fatal error",
    3: "invalid checksum, data damaged",
    4: "attempt to modify an archive locked by 'k' command",
    5: "write error",
    6: "file open error",
    7: "wrong command line option",
    8: "not enough memory",
    9: "file create error",
    10: "no files matching the specified mask were found",
    11: "wrong password",
    12: "read error",
    13: "bad archive",
    255: "user stopped the process",
}

# Internal sentinel: RAR was killed by backuper after the caller's timeout.
KILLED_BY_TIMEOUT = -1


def find_rar(explicit: str | None = None) -> Path:
    """Locate Rar.exe: explicit path, next to the exe / project root, cwd, then PATH.

    In a frozen build (PyInstaller onefile) ``Path(__file__)`` lives in the
    bundle's temp extraction dir, so the directory of ``sys.executable`` is
    checked first — shipping ``backuper.exe`` next to ``Rar.exe`` just works.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "Rar.exe")
    project_root = Path(__file__).resolve().parent.parent
    candidates.append(project_root / "Rar.exe")
    candidates.append(Path.cwd() / "Rar.exe")
    for cand in candidates:
        if cand.is_file():
            return cand
    on_path = shutil.which("rar") or shutil.which("Rar.exe") or shutil.which("rar.exe")
    if on_path:
        return Path(on_path)
    searched = "\n  ".join(str(c) for c in candidates)
    raise FileNotFoundError(
        f"Rar.exe not found. Searched:\n  {searched}\n  PATH\n"
        f"Pass --rar PATH explicitly."
    )


def decode_rar_output(raw: bytes) -> str:
    """Decode RAR text output: honour BOM, try UTF-8, fall back to OEM cp866."""
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16")
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp866", errors="replace")


def write_list_file(path: Path | str, names: list[str], bom: bool = False) -> Path:
    """Write a RAR @listfile in UTF-8, one absolute name per line.

    Pair with the '-scfl' switch so RAR reads the list as UTF-8.
    """
    path = Path(path)
    text = "\r\n".join(names) + "\r\n"
    data = text.encode("utf-8")
    if bom:
        data = codecs.BOM_UTF8 + data
    path.write_bytes(data)
    return path


def winapi_path(path: Path | str) -> str:
    r"""Return a \\?\ prefixed path (win32 namespace) so Python can cross MAX_PATH."""
    p = os.path.abspath(str(path))
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):  # UNC share
        return "\\\\?\\UNC" + p[1:]
    return "\\\\?\\" + p


def _rar_password_stdin(password: bytes | None) -> tuple[list[str], bytes | None]:
    """Stdin password transport: (bare-switch args, stdin payload).

    The archive password NEVER goes on the command line — RAR's
    '-p<secret>' argv form would leak into process lists and Rar.exe's
    own activity log. Instead the caller appends the returned bare '-p'
    switch to its args and writes the returned payload (the password
    plus a CRLF line end, accepted by RAR 7.22) to RAR's single password
    prompt on stdin. The secret therefore appears in RarResult.cmd only
    as the harmless '-p' token.

    password=None (default) restores the legacy behaviour: no switch and
    a None payload (run() then serves RAR from DEVNULL). Callers pass
    the pair straight through — e.g. ``args += pw_args`` and
    ``stdin_bytes=stdin_payload`` — so every call site stays uniform.

    Should any future code reintroduce an argv password form, every args
    formatting site must pass the list through redact() before logging.
    """
    if password is None:
        return [], None
    if not isinstance(password, bytes):
        raise TypeError("password must be bytes (encode str at the call site)")
    if not password:
        raise ValueError("password must not be an empty bytes string")
    return ["-p"], password + b"\r\n"


def redact(args: Iterable[str], password: bytes | None = None) -> list[str]:
    """Return a log-safe copy of a RAR args list with the password removed.

    Defensive guardship: today the password never appears in argv (it
    travels via stdin, see _rar_password_stdin), but if any future code
    switches to RAR's '-p<secret>' argv form, everything that formats
    RarResult.cmd or the raw args (e.g. the archiver error report at
    archiver.py's cmd join) must route the list through this helper
    first. Occurrences of the secret are replaced with '<redacted>',
    so '-p<secret>' degrades to a readable '-p<redacted>' token; a bare
    '-p' (stdin mode) contains no secret and passes through unchanged.
    Returns a plain copy when no password is given.
    """
    args = [str(a) for a in args]
    if not password:
        return args
    secret = password.decode("utf-8", errors="replace")
    return [a.replace(secret, "<redacted>") if secret else a for a in args]


@dataclass
class RarResult:
    """Outcome of one RAR invocation."""

    cmd: list[str]
    exit_code: int
    stdout_raw: bytes = b""
    stderr_raw: bytes = b""
    # (seconds_since_start, bytes) stdout chunks, captured when requested.
    stdout_chunks: list[tuple[float, bytes]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def exit_description(self) -> str:
        if self.exit_code == KILLED_BY_TIMEOUT:
            return "killed by backuper after timeout"
        return RAR_EXIT_DESCRIPTIONS.get(self.exit_code, "unknown exit code")

    def stdout(self) -> str:
        return decode_rar_output(self.stdout_raw)

    def stderr(self) -> str:
        return decode_rar_output(self.stderr_raw)

    def warning_lines(self) -> list[str]:
        """All lines that look like warnings/errors in either stream."""
        lines = []
        for line in (self.stdout() + "\n" + self.stderr()).splitlines():
            up = line.upper()
            if ("WARNING" in up or "ERROR" in up or "CANNOT" in up
                    or "ПРЕДУПРЕЖД" in up or "ОШИБ" in up
                    or "НЕВОЗМОЖНО" in up
                    or "НЕ УДАЕТСЯ" in up or "НЕ УДАЁТСЯ" in up
                    or "ОБНАРУЖЕН" in up):
                lines.append(line.strip())
        return lines


class RarRunner:
    """Runs the RAR executable and captures everything it produces."""

    def __init__(self, rar_path: Path | str):
        self.rar_path = Path(rar_path)
        if not self.rar_path.is_file():
            raise FileNotFoundError(f"RAR executable not found: {self.rar_path}")

    def run(
        self,
        args: list[str],
        *,
        cwd: Path | str | None = None,
        stdin_bytes: bytes | None = None,
        track_stdout: bool = False,
        timeout: float | None = None,
        stdout_callback: Callable[[bytes], None] | None = None,
    ) -> RarResult:
        """Execute RAR once.

        stdout, stderr and stdin are each served by a dedicated daemon
        thread, so a chatty RAR can never deadlock against a full pipe
        while the main thread waits (large listfiles used to open a
        deadlock window here). The main thread only does proc.wait().

        timeout=None (default) waits forever: production create/extract
        of 10 GB+ archives runs long, and a hung RAR is better surfaced
        by the user via Ctrl+C than killed silently. Callers doing tiny
        operations (version probe, listing) pass explicit short timeouts.
        On timeout expiry the process is killed and exit_code is -1
        (KILLED_BY_TIMEOUT sentinel; 255 stays RAR's "user stopped").

        track_stdout=True records timestamped stdout chunks (progress
        observation); stdout_callback, when given, is invoked from the
        stdout pump thread with each raw chunk as it arrives. If the
        callback raises, the exception is re-raised after the process
        has finished (the pipe is kept drained to avoid deadlocking RAR).

        On KeyboardInterrupt the process is killed, reaped, and the
        exception re-raised (the job layer cleans up its tmp files).
        """
        cmd = [str(self.rar_path)] + [str(a) for a in args]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
        started = time.monotonic()

        stderr_box: dict[str, bytes] = {"data": b""}
        out_parts: list[bytes] = []
        chunks: list[tuple[float, bytes]] = []
        error_box: list[BaseException] = []

        def pump_stderr() -> None:
            try:
                stderr_box["data"] = proc.stderr.read()
            except OSError:
                pass
            finally:
                try:
                    proc.stderr.close()
                except OSError:
                    pass

        def pump_stdout() -> None:
            try:
                while True:
                    block = proc.stdout.read1(65536)
                    if not block:
                        break
                    out_parts.append(block)
                    if track_stdout:
                        chunks.append((time.monotonic() - started, block))
                    if stdout_callback is not None:
                        try:
                            stdout_callback(block)
                        except Exception as exc:  # noqa: BLE001
                            error_box.append(exc)
            except OSError:
                pass
            finally:
                try:
                    proc.stdout.close()
                except OSError:
                    pass

        def feed_stdin() -> None:
            try:
                proc.stdin.write(stdin_bytes)
                proc.stdin.flush()
            except OSError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        threads = [
            threading.Thread(target=pump_stdout, daemon=True),
            threading.Thread(target=pump_stderr, daemon=True),
        ]
        if stdin_bytes is not None:
            threads.append(threading.Thread(target=feed_stdin, daemon=True))

        exit_code: int
        try:
            for thread in threads:
                thread.start()
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                exit_code = KILLED_BY_TIMEOUT
        except KeyboardInterrupt:
            proc.kill()
            proc.wait()
            raise
        finally:
            # The process is gone; the pumps only need to hit EOF. A short
            # join keeps a pathological pipe from hanging run() forever.
            # (Threads may not all have started if KeyboardInterrupt hit
            # early — ident is None for those.)
            for thread in threads:
                if thread.ident is not None:
                    thread.join(timeout=10.0)

        if error_box:
            raise error_box[0]

        return RarResult(
            cmd=cmd,
            exit_code=exit_code,
            stdout_raw=b"".join(out_parts),
            stderr_raw=stderr_box.get("data", b""),
            stdout_chunks=chunks,
        )


# --------------------------------------------------------------------------
# Higher-level RAR operations (still the archiver-swap seam).
# --------------------------------------------------------------------------

_RAR_VERSION_RE = re.compile(r"RAR\s+(\d+\.\d+)")
# Recognises the first line of RAR's trial-version banner in any
# language we support (English "Copyright", Russian "Авторские права").
_RAR_COPYRIGHT_RE = re.compile(r"RAR\s+\d+\.\d+\b")
_RAR_BANNER_RE = _RAR_COPYRIGHT_RE

# Canonicalisation maps for `rar lt` output (Russian builds -> English keys).
LT_LABEL_ALIASES = {
    "Имя": "Name",
    "Тип": "Type",
    "Размер": "Size",
    "В архиве": "Packed size",
    "Сжатие": "Ratio",
    "Изменён": "Modified",
    "Изменен": "Modified",
    "Атрибуты": "Attributes",
    "Базовая ОС": "Host OS",
    "Архивация": "Compression",
    "Цель": "Target",
}
LT_TYPE_ALIASES = {
    "файл": "File",
    "каталог": "Folder",
    "сервис": "service",
    "альтернативный поток данных ntfs": "NTFS alternate data stream",
}


def rar_version(runner: RarRunner) -> str:
    """Return the RAR version, e.g. '7.22', from a bare `Rar.exe` probe."""
    res = runner.run([], timeout=30.0)
    text = res.stdout() + "\n" + res.stderr()
    m = _RAR_VERSION_RE.search(text)
    if not m:
        head = text.strip().splitlines()[:2]
        raise RuntimeError(
            f"could not determine RAR version (exit {res.exit_code}); "
            f"output head: {head!r}")
    return m.group(1)


def detect_rar_language(runner: RarRunner) -> str:
    """Detect whether the installed RAR speaks Russian or English."""
    res = runner.run([], timeout=30.0)
    text = decode_rar_output(res.stdout_raw + res.stderr_raw)
    if "Пробная версия" in text or "Авторские права" in text:
        return "ru"
    if "Trial version" in text or "Copyright" in text:
        return "en"
    return "unknown"


def strip_rar_banner(text: str) -> str:
    """Drop the trial-version preamble from the very start of RAR output.

    Removes leading lines matching 'RAR <ver> ... Copyright' and lines
    starting with 'Trial version' (plus blank lines interleaved before
    the first real line). Never strips anything after the first real
    line, and banner lines must never be classified as warnings.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            i += 1
            continue
        if _RAR_BANNER_RE.search(lines[i]):
            i += 1
            continue
        if (stripped.startswith("Trial version")
                or stripped.startswith("Пробная версия")
                or stripped.startswith("Unregistered copy")
                or stripped.startswith("Незарегистрированная копия")
                or "Unregistered copy" in stripped
                or "Незарегистрированная копия" in stripped):
            i += 1
            continue
        break
    return "\n".join(lines[i:])


def parse_lt(text: str) -> list[dict]:
    """Parse `rar lt` output into per-item key/value blocks.

    Items are separated by blank lines; a block is accepted once it has
    a 'Name' key (this skips the archive header block). A line without
    a 'key: value' shape continues the previous value.
    """
    entries: list[dict] = []
    current: dict = {}
    for line in text.splitlines():
        if not line.strip():
            if "Name" in current:
                entries.append(current)
            current = {}
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip():
            raw_key = key.strip()
            canon_key = LT_LABEL_ALIASES.get(raw_key, raw_key)
            val = value.strip()
            if canon_key == "Type":
                val = LT_TYPE_ALIASES.get(val.lower(), val)
            current[canon_key] = val
        elif current:
            # continuation of the previous value
            last = list(current)[-1]
            current[last] += " " + line.strip()
    if "Name" in current:
        entries.append(current)
    return entries


def list_entries(
    runner: RarRunner, archive: Path, *, password: bytes | None = None
) -> list[dict]:
    """`rar lt -scfr` the archive and return parsed per-entry dicts.

    Callers rely on the keys Name, Type (File/Folder/service),
    Size (UNPACKED size, string) and Modified.

    ``password`` (optional, bytes) goes via the bare ``-p`` switch plus
    the stdin payload (see _rar_password_stdin). With plain ``-p``
    encryption the headers stay open: listing succeeds even with
    password=None (RAR issues no prompt and consumes nothing from
    stdin; passing the payload anyway is harmless and keeps encrypted-
    header archives testable).
    """
    pw_args, stdin_payload = _rar_password_stdin(password)
    res = runner.run(
        ["lt", "-scfr", *pw_args, str(archive)],
        cwd=None,
        timeout=120.0,
        stdin_bytes=stdin_payload)
    if res.exit_code != 0:
        raise RuntimeError(
            f"rar lt failed on {archive.name}: exit {res.exit_code} "
            f"({res.exit_description}); output tail: "
            f"{res.stdout().strip().splitlines()[-10:]}")
    return parse_lt(strip_rar_banner(res.stdout()))


def test_archive(
    runner: RarRunner,
    archive: Path,
    *,
    progress_callback: Callable[[bytes], None] | None = None,
    password: bytes | None = None,
) -> int:
    """`rar t` the archive with unlimited time. 0 = ok; 3 = damaged.

    ``progress_callback`` (optional) receives raw stdout chunks from the
    pump thread; used by the verify layer for a live percent indicator.

    ``password`` (optional, bytes) is supplied via the bare ``-p`` switch
    plus the stdin payload — never as ``-p<secret>``. This completely
    prevents the interactive password prompt; a WRONG password surfaces
    as exit 11 ("wrong password") instead of a hang (verified, RAR 7.22).
    """
    pw_args, stdin_payload = _rar_password_stdin(password)
    return runner.run(
        ["t", "-scfr", *pw_args, str(archive)],
        stdin_bytes=stdin_payload,
        stdout_callback=progress_callback).exit_code


def repair(
    runner: RarRunner, archive: Path, *, password: bytes | None = None
) -> Path:
    """Repair a damaged archive from its recovery record (`rar r -y`).

    RAR writes the repaired copy as 'fixed.<archive basename>' into the
    PROCESS CWD (probed: not next to the archive), so this runs with
    cwd=archive.parent to make the fixed file land next to the original
    deterministically. Returns the fixed file's path.

    Note the exact name: 'fixed.' + full basename, no extra '.rar'
    appended (rr.rar -> fixed.rr.rar, arch.tmp -> fixed.arch.tmp).

    ``password`` (optional, bytes) is only needed if the repair flow then
    re-reads encrypted content from the (fixed) archive; it travels via
    the bare ``-p`` switch + stdin like everywhere else. Recovery-record
    repair itself does not need the password, so password=None keeps the
    legacy no-stdin behaviour.
    """
    pw_args, stdin_payload = _rar_password_stdin(password)
    res = runner.run(
        ["r", "-y", *pw_args, str(archive)],
        cwd=archive.parent,
        stdin_bytes=stdin_payload)
    if res.exit_code != 0:
        text = res.stdout() + "\n" + res.stderr()
        tail = "\n".join(text.strip().splitlines()[-15:])
        raise RuntimeError(
            f"rar r failed on {archive.name}: exit {res.exit_code} "
            f"({res.exit_description}); output tail:\n{tail}")
    for name in (f"fixed.{archive.name}", f"fixed.{archive.name}.rar"):
        fixed = archive.parent / name
        if fixed.is_file():
            return fixed
    raise RuntimeError(
        f"rar r reported success (exit 0) but no fixed file appeared next to "
        f"{archive}; fixed.* found: "
        f"{[p.name for p in archive.parent.glob('fixed.*')]}")


def read_service_members(
    runner: RarRunner, archive: Path, members: Iterable[str],
    *, password: bytes | None = None,
) -> dict[str, bytes]:
    r"""Read stored members (e.g. '.backup/manifest.json') as bytes.

    One `Rar.exe x` call extracts all requested members into a fresh temp
    dir (quick-open aware, so it does not scan the whole archive), then the
    files are read back. Extraction is used instead of piping (`p`) because
    RAR verifies CRCs and exits non-zero on damage. Member names are passed
    with backslashes (forward slashes -> exit 10) and the destination must be
    a plain short ASCII path (a \\?\ prefixed dest -> exit 9). Keys of the
    result are the member strings exactly as passed in.

    ``password`` (optional, bytes) goes via the bare ``-p`` switch + stdin.
    The plain .backup/ service members are stored UNENCRYPTED, so they must
    keep reading without one: default password=None preserves the legacy
    behaviour (no switch, stdin served from DEVNULL).
    """
    wanted = list(dict.fromkeys(members))
    if not wanted:
        return {}
    bs = [m.replace("/", "\\") for m in wanted]
    tempdir = Path(tempfile.mkdtemp(prefix="backuper_read_"))
    try:
        pw_args, stdin_payload = _rar_password_stdin(password)
        args = [
            "x", "-y", "-scfr", *pw_args, str(archive),
            *bs, str(tempdir) + os.sep,
        ]
        res = runner.run(args, stdin_bytes=stdin_payload)
        if res.exit_code != 0:
            lines = [
                line for line in (res.stdout() + res.stderr()).splitlines()
                if line.strip()
            ]
            tail = " ".join(lines[-5:])
            raise RuntimeError(
                f"rar x members exited {res.exit_code} "
                f"({res.exit_description}): {tail}")
        out: dict[str, bytes] = {}
        for member, member_bs in zip(wanted, bs, strict=True):
            extracted = tempdir.joinpath(*member_bs.split("\\"))
            if not extracted.is_file():
                landed = sorted(
                    str(p.relative_to(tempdir))
                    for p in tempdir.rglob("*") if p.is_file())[:5]
                raise RuntimeError(
                    f"rar x reported success but {member!r} did not land in "
                    f"the temp dir; extracted: {landed}")
            try:
                data = extracted.read_bytes()
            except OSError:
                data = Path(winapi_path(extracted)).read_bytes()
            out[member] = data
        return out
    finally:
        shutil.rmtree(winapi_path(tempdir), ignore_errors=True)


def read_service_member(runner: RarRunner, archive: Path, member: str) -> bytes:
    """Read one stored member (e.g. '.backup/manifest.json') as bytes."""
    return read_service_members(runner, archive, [member])[member]


def create_step(
    runner: RarRunner,
    target: Path,
    cwd: Path,
    names: list[str],
    *,
    final: bool,
    compression: int,
    progress_callback: Callable[[bytes], None] | None = None,
    bom: bool = False,
    password: bytes | None = None,
) -> RarResult:
    """One `rar a` step of the production create flow.

    The tool builds an archive in TWO steps into the SAME target:
    step 1 (final=False) adds the .backup/ service files from a staging
    dir; step 2 (final=True) adds the user files with cwd=source root and
    finishes the archive with the quick-open record and a 5% recovery
    record. The caller checks RarResult.ok.

    names are relative paths (against cwd) with backslash separators;
    empty dirs must appear WITHOUT a trailing separator ('dir\\' is
    silently ignored by RAR, exit 0) — normalized here defensively.

    progress_callback, when given, receives raw stdout chunks (percent
    progress lines) from the pump thread. Runs without a timeout: the
    create of a 10 GB+ archive may take hours.

    Every call passes ``-w<target.parent>`` so RAR's archive-modification
    work file (``__rar_<pid>.<tid>.rartemp``) stays in the epoch dir next
    to the archive. Without ``-w`` that file lands in the PROCESS CWD —
    the source root on the content step — leaving a multi-GB orphan on the
    source disk if the run is killed (DIAGNOSTICS #15).

    ``password`` (optional, bytes) is fed to RAR ONLY via stdin: the args
    get the bare ``-p`` switch (never ``-p<secret>`` — that would leak
    into process lists and Rar.exe logs) and the payload password+CRLF is
    written to RAR's single prompt. Verified against RAR 7.22: exactly
    one prompt, no re-enter; every newly added entry is encrypted, and a
    second ``a`` into the same archive accepts the stdin line the same
    way. The secret appears nowhere in RarResult.cmd.
    """
    fd, tmpname = tempfile.mkstemp(prefix="backuper_lst_", suffix=".lst")
    os.close(fd)
    list_path = Path(tmpname)
    try:
        normalized = [n.replace("/", "\\").rstrip("\\") for n in names]
        write_list_file(list_path, normalized, bom=bom)
        pw_args, stdin_payload = _rar_password_stdin(password)
        # -r- disables recursion: an explicitly named directory (e.g. one of
        # the leaf empty dirs passed in names) is stored as a folder entry
        # only, without RAR pulling in its on-disk contents. Without it, RAR
        # archives the whole subtree of such a dir (including excluded
        # extensions, excluded dirs like .git, and junction/symlink targets),
        # which both violates the scanner's exclusion policy and breaks the
        # post-archive cross-check.
        args = ["a", "-y", "-scflr", "-os", "-r-", f"-m{compression}"]
        if final:
            args += ["-qo+", "-rr5"]
        args += pw_args
        # Without -w RAR puts its __rar_<pid>.<tid>.rartemp modification
        # work file into the PROCESS CWD (the source root on the content
        # step). Pin it into the epoch dir next to the archive: it never
        # lands on the source disk, stays on the archive's volume (no
        # cross-volume temp), and orphans from killed runs are swept by
        # archiver.sweep_stale_rartemp().
        workdir = Path(os.path.abspath(target.parent))
        args += [f"-w{workdir}", str(target), "@" + str(list_path)]
        return runner.run(
            args,
            cwd=cwd,
            stdin_bytes=stdin_payload,
            track_stdout=True,
            stdout_callback=progress_callback,
        )
    finally:
        try:
            list_path.unlink()
        except OSError:
            pass
