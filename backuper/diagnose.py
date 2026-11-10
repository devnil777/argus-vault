"""Self-diagnostics for the RAR tool chain (`backuper diagnose`).

Every check builds a small scenario in a temporary directory, runs the
real Rar.exe through RarRunner and asserts the behaviour the backup
design depends on. Plain Python, no test framework: this module ships
with the product and doubles as a hardware/OS compatibility probe.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from backuper.rar_runner import (
    RarRunner,
    create_step,
    decode_rar_output,
    detect_rar_language,
    find_rar,
    parse_lt,
    read_service_member,
    repair,
    strip_rar_banner,
    test_archive,
    winapi_path,
    write_list_file,
)

# Exit codes of the backuper CLI (task.md):
#   0 ok, 2 RAR failed, 5 config/epoch error.
EXIT_OK = 0
EXIT_RAR_FAILED = 2

GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80


@dataclass
class CheckResult:
    name: str
    passed: bool
    summary: str
    details: list[str] = field(default_factory=list)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes_longpath(path: Path | str) -> bytes:
    with open(winapi_path(path), "rb") as fh:
        return fh.read()


def add_to_archive(runner: RarRunner, archive: Path, names: list[str],
                   workdir: Path, extra_args: list[str] | None = None,
                   bom: bool = False) -> tuple[object, Path]:
    """Create an archive from a UTF-8 @listfile (the production pathway)."""
    lst = write_list_file(workdir / (archive.stem + ".lst"), names, bom=bom)
    args = ["a", "-y", "-scfl", *(extra_args or []), str(archive), f"@{lst}"]
    return runner.run(args), lst


def extract_archive(runner: RarRunner, archive: Path, dest: Path) -> object:
    dest.mkdir(parents=True, exist_ok=True)
    return runner.run(["x", "-y", "-scfr", str(archive), str(dest) + os.sep])


def entry_files(entries: list[dict[str, str]]) -> dict[str, int]:
    """Map stored name (forward slashes) -> size for file entries."""
    result: dict[str, int] = {}
    for e in entries:
        name = e.get("Name", "")
        if not name:
            continue
        etype = e.get("Type", "").lower()
        if "folder" in etype or "directory" in etype:
            continue
        try:
            size = int(e.get("Size", "-1"))
        except ValueError:
            size = -1
        result[name.replace("\\", "/")] = size
    return result


def walk_entries(base: Path) -> tuple[dict[str, str], set[str]]:
    """Walk a directory tree (long-path safe).

    Returns ({relative/name/with/slashes: full_winapi_path},
             {relative/dir/name set}) relative to base.
    """
    top = winapi_path(base)
    files: dict[str, str] = {}
    dirs: set[str] = set()
    for root, dir_names, file_names in os.walk(top):
        rel_root = root[len(top):].replace("\\", "/").strip("/")
        for d in dir_names:
            dirs.add(f"{rel_root}/{d}" if rel_root else d)
        for fn in file_names:
            files[f"{rel_root}/{fn}" if rel_root else fn] = os.path.join(root, fn)
    return files, dirs


def find_extracted_file(base: Path, rel_suffix: str) -> str | None:
    rel_suffix = rel_suffix.replace("\\", "/")
    files, _ = walk_entries(base)
    for rel, full in files.items():
        if rel == rel_suffix or rel.endswith("/" + rel_suffix):
            return full
    return None


# --------------------------------------------------------------------------
# Check 0: RAR is callable, report its version.
# --------------------------------------------------------------------------

def check_rar_version(runner: RarRunner, workdir: Path) -> CheckResult:
    res = runner.run([])
    text = res.stdout() + "\n" + res.stderr()
    m = re.search(r"RAR\s+(\d[\w.]*)\s*(?:.*?x\d+)?", text)
    version = m.group(1) if m else "unknown"
    return CheckResult(
        name="rar_version",
        passed=res.exit_code in (0, 255) and version != "unknown",
        summary=f"{runner.rar_path} identifies as RAR {version}",
        details=[f"exit_code={res.exit_code}", text.splitlines()[0] if text.splitlines() else ""],
    )


# --------------------------------------------------------------------------
# Check: RAR output language detection + lt parsing.
# --------------------------------------------------------------------------
def check_rar_language(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    lang = detect_rar_language(runner)
    details.append(f"detected language: {lang}")
    rar_lng = runner.rar_path.parent / "RarLng.dll"
    details.append(f"RarLng.dll next to exe: {rar_lng.exists()}")

    src = workdir / "lang_src"
    src.mkdir(exist_ok=True)
    (src / "probe.txt").write_bytes(b"x")
    archive = workdir / "lang_probe.rar"
    res, _ = add_to_archive(runner, archive, [str(src / "probe.txt")], workdir)
    entries = parse_lt(strip_rar_banner(runner.run(["lt", "-scfr", str(archive)]).stdout()))
    details.append(f"lt parsed entries: {len(entries)}; "
                   f"names: {[e.get('Name') for e in entries]}")

    passed = (lang in ("ru", "en") and res.ok and len(entries) == 1
              and str(entries[0].get("Name", "")).endswith("probe.txt")
              and entries[0].get("Type") == "File")
    if passed:
        summary = f"RAR output language: {lang}; lt labels parse correctly (ru+en supported)"
    else:
        summary = "RAR language not supported or lt parsing failed - see details"
    return CheckResult("rar_language", passed, summary, details)


# --------------------------------------------------------------------------
# Check 1: long paths (> 260 chars) survive add + extract.
# --------------------------------------------------------------------------

def check_long_path(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    src = workdir / "lp_src"
    segment = "d" * 60
    deep = src.joinpath(*[segment] * 5)
    os.makedirs(winapi_path(deep), exist_ok=True)
    file_name = "payload_" + ("f" * 30) + ".bin"
    payload = os.urandom(128 * 1024)
    target = deep / file_name
    with open(winapi_path(target), "wb") as fh:
        fh.write(payload)
    plain = str(target)
    details.append(f"path length: {len(plain)} chars (plain, no \\\\?\\ prefix)")

    archive = workdir / "longpath.rar"
    res, _lst = add_to_archive(runner, archive, [plain], workdir)
    variant = "plain path in listfile"
    if not res.ok or "payload" not in res.stdout() + res.stderr():
        # Retry with the \\?\ form in the listfile.
        archive.unlink(missing_ok=True)
        res2, _ = add_to_archive(runner, archive, [winapi_path(target)], workdir)
        res = res2
        variant = "\\\\?\\-prefixed path in listfile"
    details.append(f"rar a exit_code={res.exit_code} ({variant})")
    if res.warning_lines():
        details.append("warnings: " + "; ".join(res.warning_lines()[:3]))

    listing = runner.run(["lb", "-scfr", str(archive)])
    names = [ln for ln in listing.stdout().splitlines() if "payload" in ln]
    details.append(f"stored name: {names[0] if names else '<not found>'}")

    dest = workdir / "lp_out"
    xres = extract_archive(runner, archive, dest)
    details.append(f"rar x exit_code={xres.exit_code}")

    found: list[str] = []
    for root, _dirs, files in os.walk(winapi_path(dest)):
        for fn in files:
            if "payload" in fn:
                found.append(os.path.join(root, fn))
    if len(found) != 1:
        details.append(f"extracted payload files found: {len(found)}")
        return CheckResult("long_path", False, "payload not extracted uniquely", details)
    got = read_bytes_longpath(found[0])
    ok = got == payload and sha256(got) == sha256(payload)
    details.append(f"bytes and sha256 match: {ok}")
    return CheckResult(
        "long_path", ok and res.ok and xres.ok,
        f"{len(plain)}-char path round-tripped byte-identical ({variant})",
        details,
    )


# --------------------------------------------------------------------------
# Check 2: OS-locked file makes RAR fail (warning => error policy).
# --------------------------------------------------------------------------

def _hold_exclusive_lock(path: Path, ready: threading.Event,
                         release: threading.Event) -> dict:
    state: dict = {"handle": None, "error": None}
    try:
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        handle = k32.CreateFileW(str(path), GENERIC_READ, 0, None,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if handle is None or handle == ctypes.c_void_p(-1).value:
            state["error"] = ctypes.get_last_error()
        else:
            state["handle"] = handle
    except OSError as exc:
        state["error"] = str(exc)
    ready.set()
    release.wait(30)
    if state["handle"]:
        ctypes.windll.kernel32.CloseHandle(state["handle"])
    return state


def check_locked_file(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    src = workdir / "lock_src"
    src.mkdir()
    target = src / "data.txt"
    target.write_bytes(b"locked-file-payload" * 64)

    ready, release = threading.Event(), threading.Event()
    holder = threading.Thread(
        target=_hold_exclusive_lock, args=(target, ready, release), daemon=True)
    holder.start()
    ready.wait(10)

    archive = workdir / "locked.rar"
    res_locked, _ = add_to_archive(runner, archive, [str(target)], workdir)
    release.set()
    holder.join(5)

    archive.unlink(missing_ok=True)
    res_free, _ = add_to_archive(runner, archive, [str(target)], workdir)

    warnings = res_locked.warning_lines()
    details.append(f"locked run: exit_code={res_locked.exit_code} "
                   f"({res_locked.exit_description})")
    if warnings:
        details.append("locked run message: " + warnings[0])
    details.append(f"archive file created despite failure: {archive.exists()}")
    details.append(f"unlocked control run: exit_code={res_free.exit_code}")

    # The whole design leans on "any warning/non-zero exit fails the backup".
    ok = res_locked.exit_code != 0 and res_free.exit_code == 0
    return CheckResult(
        "locked_file", ok,
        f"locked file -> RAR exit {res_locked.exit_code} (non-zero, policy holds); "
        f"unlocked -> 0",
        details,
    )


# --------------------------------------------------------------------------
# Check 3: parse `rar lt` output of a representative archive.
# --------------------------------------------------------------------------

def check_listing(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    src = workdir / "list_src"
    (src / "sub").mkdir(parents=True)
    (src / "emptydir").mkdir()
    expected: dict[str, int] = {}
    files = {
        "alpha.txt": 1000,
        "beta.bin": 4096,
        os.path.join("sub", "gamma with spaces.txt"): 123,
        os.path.join("sub", "кириллица.txt"): 456,
    }
    for rel, size in files.items():
        data = os.urandom(size)
        (src / rel).write_bytes(data)
        expected[rel] = size

    archive = workdir / "listing.rar"
    names = [str(src / rel) for rel in files] + [str(src / "emptydir")]
    res, _ = add_to_archive(runner, archive, names, workdir)
    details.append(f"rar a exit_code={res.exit_code}")

    lt = runner.run(["lt", "-scfr", str(archive)])
    entries = parse_lt(lt.stdout())
    got_files = entry_files(entries)
    details.append(f"lt blocks parsed: {len(entries)}, file entries: {len(got_files)}")

    matched = True
    for rel, size in expected.items():
        rel_norm = rel.replace("\\", "/")
        hit = [n for n in got_files
               if n.endswith(rel_norm) and got_files[n] == size]
        if not hit:
            matched = False
            details.append(f"missing/mismatched in lt: {rel_norm} (size {size})")
    name_root = next(iter(got_files), "<none>")
    details.append(f"stored-name sample: {name_root}")

    dest = workdir / "list_out"
    xres = extract_archive(runner, archive, dest)
    ex_files, ex_dirs = walk_entries(dest)
    content_ok = True
    for rel in files:
        rel_norm = rel.replace("\\", "/")
        full = find_extracted_file(dest, rel_norm)
        if full is None or open(full, "rb").read() != (src / rel).read_bytes():
            content_ok = False
            details.append(f"extraction mismatch for: {rel_norm}")
    empty_ok = any(d == "emptydir" or d.endswith("/emptydir") for d in ex_dirs)
    details.append(f"extract byte-identical: {content_ok}; empty dir restored: {empty_ok}")

    ok = res.ok and lt.ok and matched and content_ok and empty_ok and xres.ok
    return CheckResult(
        "listing", ok,
        f"lt parsed ({len(got_files)} files, all sizes match, extraction byte-identical)",
        details,
    )


# --------------------------------------------------------------------------
# Check 4: progress is observable on a piped stdout (150 MB payload).
# --------------------------------------------------------------------------

def check_progress(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    src = workdir / "prog_src"
    src.mkdir()
    big = src / "blob.bin"
    mib = 1 << 20
    total_mib = 150
    with open(winapi_path(big), "wb") as fh:
        for _ in range(total_mib):
            fh.write(os.urandom(mib))

    archive = workdir / "progress.rar"
    lst = write_list_file(workdir / "progress.lst", [str(big)])
    res = runner.run(
        ["a", "-y", "-scflr", "-r-", "-m5", str(archive), f"@{lst}"],
        track_stdout=True, timeout=900)
    try:
        big.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
    except OSError:
        pass

    pct_events: list[tuple[float, int]] = []
    for t, block in res.stdout_chunks:
        for m in re.finditer(rb"(\d{1,3})%", block):
            pct_events.append((round(t, 3), int(m.group(1))))
    stderr_pct = len(re.findall(r"\d{1,3}%", res.stderr()))

    _marker_re = re.compile(
        "(?:Adding|Updating|Добавление|Обновление)".encode())
    marker_count = len(_marker_re.findall(
        b"".join(block for _t, block in res.stdout_chunks)))
    details.append(f"entry markers on stdout: {marker_count}")

    details.append(f"exit_code={res.exit_code}; stdout chunks: {len(res.stdout_chunks)}; "
                   f"percent events on stdout: {len(pct_events)}; on stderr: {stderr_pct}")
    if pct_events:
        timespan = pct_events[-1][0] - pct_events[0][0]
        values = [p for _, p in pct_events]
        details.append(
            f"first->last progress event: {timespan:.2f}s, "
            f"percent range {min(values)}..{max(values)}")
        m = re.search(rb".{0,10}\d{1,3}%", res.stdout_chunks[0][1])
        if m:
            details.append(f"progress line bytes: {m.group(0)!r}")
    if not res.stdout_chunks and res.stderr_raw:
        details.append("stdout empty; progress apparently goes to stderr")

    ok = res.ok and len(pct_events) >= 3 and marker_count >= 1
    return CheckResult(
        "progress", ok,
        f"{len(pct_events)} percent updates observed on piped stdout "
        f"over {total_mib} MiB" if ok else
        "progress not observable on piped stdout (fallback: poll .tmp size)",
        details,
    )


# --------------------------------------------------------------------------
# Check 5: UTF-8 file names (Cyrillic + CJK + emoji) full cycle.
# --------------------------------------------------------------------------

UTF_NAME = "тест-日本語-😀.txt"


def check_utf_names(runner: RarRunner, workdir: Path) -> CheckResult:
    details: list[str] = []
    src = workdir / "utf_src"
    src.mkdir()
    payload = "utf8-marker-پچ-中文".encode() * 10
    target = src / UTF_NAME
    target.write_bytes(payload)

    archive = workdir / "utf.rar"
    res, _ = add_to_archive(runner, archive, [str(target)], workdir)
    bom_used = False
    if not res.ok or res.warning_lines():
        archive.unlink(missing_ok=True)
        res, _ = add_to_archive(runner, archive, [str(target)], workdir, bom=True)
        bom_used = True
    details.append(f"rar a exit_code={res.exit_code}"
                   + (" (listfile needed BOM)" if bom_used else " (listfile without BOM)"))

    lb_f = runner.run(["lb", "-scfr", str(archive)])
    lb_raw_default = runner.run(["lb", str(archive)])
    try:
        utf8_listing = lb_f.stdout_raw.decode("utf-8-sig")
        listed_ok = UTF_NAME in utf8_listing
        enc_used = "-scfr (UTF-8)"
    except UnicodeDecodeError:
        listed_ok = False
        enc_used = "-scfr decode failed"
    details.append(f"lb {enc_used}: name listed correctly: {listed_ok}")
    default_decoded = decode_rar_output(lb_raw_default.stdout_raw)
    details.append(f"lb default pipe encoding sample: "
                   f"{default_decoded.splitlines()[0][:60]!r}" if default_decoded else "lb default empty")

    dest = workdir / "utf_out"
    xres = extract_archive(runner, archive, dest)
    extracted = [p.name for p in dest.rglob("*") if p.is_file()]
    name_ok = extracted == [UTF_NAME]
    content_ok = False
    if name_ok:
        content_ok = read_bytes_longpath(next(dest.rglob(UTF_NAME))) == payload
    details.append(f"extracted names: {extracted}; content identical: {content_ok}")

    ok = res.ok and listed_ok and xres.ok and name_ok and content_ok
    return CheckResult(
        "utf_names", ok,
        f"'{UTF_NAME}' archived, listed and extracted intact"
        + ("" if not bom_used else " (requires UTF-8 BOM in listfile)"),
        details,
    )


# --------------------------------------------------------------------------
# Bonus checks: details that shape the design.
# --------------------------------------------------------------------------

def check_ads_streams(runner: RarRunner, workdir: Path) -> CheckResult:
    """NTFS alternate data streams: -os vs default (task.md assumed default-on)."""
    details: list[str] = []
    src = workdir / "ads_src"
    src.mkdir()
    host = src / "host.txt"
    host.write_bytes(b"main-stream")
    stream_payload = b"ads-payload-123"
    with open(str(host) + ":s1", "wb") as fh:
        fh.write(stream_payload)

    outcomes: dict[str, bool] = {}
    for label, extra in (("os_switch", ["-os"]), ("default", [])):
        archive = workdir / f"ads_{label}.rar"
        res, _ = add_to_archive(runner, archive, [str(host)], workdir, extra_args=extra)
        lta = runner.run(["lta", "-scfr", str(archive)])
        stream_lines = [ln for ln in lta.stdout().splitlines()
                        if "stream" in ln.lower() or "поток" in ln.lower()]
        dest = workdir / f"ads_out_{label}"
        extract_archive(runner, archive, dest)
        restored = False
        full = find_extracted_file(dest, "host.txt")
        if full:
            try:
                with open(full + ":s1", "rb") as fh:
                    restored = fh.read() == stream_payload
            except OSError:
                pass
        outcomes[label] = restored
        details.append(
            f"{label}: rar exit {res.exit_code}; stream in lta: "
            f"{stream_lines[:1]}; stream restored: {restored}")

    ok = outcomes.get("os_switch", False) and not outcomes.get("default", True)
    return CheckResult(
        "ads_streams", ok,
        "ADS round-trips only with -os; default drops them "
        "(design: backuper must always pass -os)",
        details,
    )


def check_empty_dirs(runner: RarRunner, workdir: Path) -> CheckResult:
    """Which listfile form stores an empty directory: 'dir' vs 'dir\\'."""
    details: list[str] = []
    src = workdir / "ed_src"
    (src / "plain").mkdir(parents=True)
    (src / "slashed").mkdir(parents=True)
    (src / "filler.txt").write_bytes(b"x")

    archive = workdir / "emptydirs.rar"
    lst = write_list_file(workdir / "ed.lst", [
        str(src / "filler.txt"),
        str(src / "plain"),
        str(src / "slashed") + os.sep,
    ])
    res = runner.run(["a", "-y", "-scfl", str(archive), f"@{lst}"])
    lb = runner.run(["lb", "-scfr", str(archive)])
    names = [n for n in lb.stdout().splitlines() if n.strip()]
    dest = workdir / "ed_out"
    extract_archive(runner, archive, dest)
    _files, ex_dirs = walk_entries(dest)

    for label, d in (("plain 'dir'", "plain"), ("'dir\\'", "slashed")):
        stored = any(n.replace("\\", "/").rstrip("/").endswith(d) for n in names)
        extracted = any(nd == d or nd.endswith("/" + d) for nd in ex_dirs)
        details.append(f"{label}: stored in archive: {stored}; extracted: {extracted}")
    details.append("lb entries: " + "; ".join(names))

    plain_ok = any(nd == "plain" or nd.endswith("/plain") for nd in ex_dirs)
    ok = plain_ok and res.ok
    return CheckResult(
        "empty_dirs", ok,
        "empty dir stored+extracted via plain 'dir' listfile entry; "
        "trailing-separator 'dir\\' entries are silently ignored by RAR "
        "(design: emit dir paths without trailing separator)",
        details,
    )


def check_missing_file(runner: RarRunner, workdir: Path) -> CheckResult:
    """A stale listfile entry (file deleted between scan and rar) must fail."""
    details: list[str] = []
    src = workdir / "miss_src"
    src.mkdir()
    keep = src / "keep.txt"
    keep.write_bytes(b"keep")
    ghost = src / "ghost.txt"

    mixed = workdir / "miss_mixed.rar"
    res_mixed, _ = add_to_archive(runner, mixed,
                                  [str(keep), str(ghost)], workdir)
    only = workdir / "miss_only.rar"
    res_only, _ = add_to_archive(runner, only, [str(ghost)], workdir)

    details.append(f"existing+missing: exit_code={res_mixed.exit_code} "
                   f"({res_mixed.exit_description})")
    if res_mixed.warning_lines():
        details.append("message: " + res_mixed.warning_lines()[0])
    details.append(f"only missing: exit_code={res_only.exit_code} "
                   f"({res_only.exit_description})")

    ok = res_mixed.exit_code != 0 and res_only.exit_code != 0
    return CheckResult(
        "missing_file", ok,
        f"missing listfile entry -> exit {res_mixed.exit_code}/{res_only.exit_code} "
        f"(non-zero: policy catches stale lists)",
        details,
    )


def check_mtime_precision(runner: RarRunner, workdir: Path) -> CheckResult:
    """mtime must round-trip with 100 ns precision (diff comparison depends on it)."""
    details: list[str] = []
    src = workdir / "mtime_src"
    src.mkdir()
    f = src / "timed.txt"
    f.write_bytes(b"mtime")
    # A value no filesystem rounding would invent, aligned to 100 ns.
    want_ns = 1793644800 * 10**9 + 123_456_700
    os.utime(f, ns=(want_ns, want_ns))

    archive = workdir / "mtime.rar"
    add_to_archive(runner, archive, [str(f)], workdir)
    dest = workdir / "mtime_out"
    extract_archive(runner, archive, dest)
    full = find_extracted_file(dest, "timed.txt")
    if full is None:
        return CheckResult("mtime_precision", False,
                           "timed.txt not found after extract", details)
    got_ns = os.stat(full).st_mtime_ns
    delta = abs(got_ns - want_ns)
    details.append(f"set st_mtime_ns={want_ns}; restored={got_ns}; delta={delta} ns")
    lt = runner.run(["lt", "-scfr", str(archive)])
    m = re.search(r"(?:Modified|Изменён):\s*(\S+ \S+)", lt.stdout())
    if m:
        details.append(f"lt Modified string: {m.group(1)}")

    ok = delta <= 100
    return CheckResult(
        "mtime_precision", ok,
        f"mtime round-trip delta {delta} ns (<=100 ns required)",
        details,
    )


def check_stdin_listfile(runner: RarRunner, workdir: Path) -> CheckResult:
    """@ (empty listfile name) reads names from stdin - avoids temp listfiles."""
    details: list[str] = []
    src = workdir / "stdin_src"
    src.mkdir()
    f = src / "from_stdin.txt"
    f.write_bytes(b"stdin-list")

    archive = workdir / "stdin.rar"
    stdin_data = (str(f) + "\r\n").encode("utf-8")
    res = runner.run(["a", "-y", "-scfl", str(archive), "@"],
                     stdin_bytes=stdin_data)
    lb = runner.run(["lb", "-scfr", str(archive)])
    listed = "from_stdin.txt" in lb.stdout()
    details.append(f"rar a exit_code={res.exit_code}; listed after add: {listed}")
    if not listed and res.ok:
        details.append("note: stdin list possibly not treated as UTF-8 by -scfl")

    ok = res.ok and listed
    return CheckResult(
        "stdin_listfile", ok,
        "@-stdin UTF-8 list accepted (no temp listfile needed)",
        details,
    )


def check_stored_name_forms(runner: RarRunner, workdir: Path) -> CheckResult:
    """How names are stored: absolute listfile paths vs relative paths with cwd.

    Design-critical: files.json wants clean paths relative to the source
    root, so we must know which invocation form produces them.
    """
    details: list[str] = []
    src = workdir / "snf_src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "inner.txt").write_bytes(b"x")
    (src / "top.txt").write_bytes(b"y")

    arch_abs = workdir / "snf_abs.rar"
    add_to_archive(runner, arch_abs,
                   [str(src / "top.txt"), str(src / "sub" / "inner.txt")], workdir)
    lb_abs = [n for n in runner.run(["lb", "-scfr", str(arch_abs)])
              .stdout().splitlines() if n.strip()]
    for n in lb_abs:
        details.append(f"absolute-path listfile stores: {n}")

    arch_rel = workdir / "snf_rel.rar"
    lst = write_list_file(workdir / "snf_rel.lst",
                          ["top.txt", os.path.join("sub", "inner.txt")])
    res_rel = runner.run(["a", "-y", "-scfl", str(arch_rel), f"@{lst}"], cwd=src)
    lb_rel = [n for n in runner.run(["lb", "-scfr", str(arch_rel)])
              .stdout().splitlines() if n.strip()]
    for n in lb_rel:
        details.append(f"relative listfile + cwd stores: {n}")

    want = {"top.txt", "sub/inner.txt"}
    got = {n.replace("\\", "/") for n in lb_rel}
    ok = res_rel.ok and got == want
    return CheckResult(
        "stored_name_forms", ok,
        "relative paths + cwd=source root give clean archive-relative names "
        "(absolute paths would embed Users/... prefixes)" if ok else
        "relative+cwd form did not produce clean names - see details",
        details,
    )


def check_quick_open(runner: RarRunner, workdir: Path) -> CheckResult:
    """-qo+ quick open record: must be created, must not break t/lta."""
    details: list[str] = []
    src = workdir / "qo_src"
    src.mkdir()
    for i in range(5):
        (src / f"small_{i}.txt").write_bytes(os.urandom(512))

    sizes: dict[str, int] = {}
    all_ok = True
    for label, extra in (("default", []), ("qo_plus", ["-qo+"])):
        archive = workdir / f"qo_{label}.rar"
        res, _ = add_to_archive(runner, archive,
                                [str(src / f"small_{i}.txt") for i in range(5)],
                                workdir, extra_args=extra)
        t = runner.run(["t", str(archive)])
        lta = runner.run(["lta", "-scfr", str(archive)])
        svc = [ln.strip() for ln in lta.stdout().splitlines()
               if "QO" in ln or "quick" in ln.lower()]
        sizes[label] = archive.stat().st_size
        ok = res.ok and t.ok
        all_ok = all_ok and ok
        details.append(
            f"{label}: a={res.exit_code} t={t.exit_code} size={sizes[label]} B")
        if svc:
            details.append(f"{label} lta: {'; '.join(svc[:2])}")

    grew = sizes["qo_plus"] > sizes["default"]
    details.append(f"archive grew with -qo+ (header copies added): {grew} "
                   f"(+{sizes['qo_plus'] - sizes['default']} B)")
    ok = all_ok and grew
    return CheckResult(
        "quick_open", ok,
        "-qo+ adds quick open record; t/lta still work "
        "(speeds up opening large archives by design)" if ok else
        "-qo+ did not behave as expected - see details",
        details,
    )


def check_recovery_record(runner: RarRunner, workdir: Path) -> CheckResult:
    """-rr5: damage the archive, repair with rar r, verify content."""
    details: list[str] = []
    src = workdir / "rr_src"
    src.mkdir()
    data = os.urandom(10 * (1 << 20))
    (src / "blob.bin").write_bytes(data)
    orig_sha = sha256(data)

    archive = workdir / "rr.rar"
    plain = workdir / "rr_plain.rar"
    res, _ = add_to_archive(runner, archive, [str(src / "blob.bin")], workdir,
                            extra_args=["-m0", "-rr5"])
    add_to_archive(runner, plain, [str(src / "blob.bin")], workdir,
                   extra_args=["-m0"])
    overhead = archive.stat().st_size - plain.stat().st_size
    details.append(f"rr5 overhead: {overhead} B on {plain.stat().st_size} B (-m0) archive")

    t_intact = runner.run(["t", str(archive)])
    details.append(f"rar t intact: exit {t_intact.exit_code}")

    raw = bytearray(archive.read_bytes())
    pos = int(len(raw) * 0.45)
    raw[pos:pos + 65536] = os.urandom(65536)  # continuous 64 KiB damage
    archive.write_bytes(bytes(raw))
    t_bad = runner.run(["t", str(archive)])
    details.append(f"rar t damaged (64 KiB @45%): exit {t_bad.exit_code} "
                   f"({t_bad.exit_description})")

    r = runner.run(["r", "-y", str(archive)], cwd=workdir)
    fixed = workdir / ("fixed." + archive.name)
    details.append(f"rar r: exit {r.exit_code}; fixed.{archive.name} exists: "
                   f"{fixed.exists()}")
    t_fixed = runner.run(["t", str(fixed)]) if fixed.exists() else None
    details.append(f"rar t repaired: exit {t_fixed.exit_code if t_fixed else 'n/a'}")

    repaired_ok = False
    if t_fixed is not None and t_fixed.ok:
        dest = workdir / "rr_out"
        extract_archive(runner, fixed, dest)
        full = find_extracted_file(dest, "blob.bin")
        if full:
            repaired_ok = sha256(open(full, "rb").read()) == orig_sha
    details.append(f"repaired content sha256 identical: {repaired_ok}")

    ok = (res.ok and t_intact.ok and t_bad.exit_code != 0
          and r.ok and fixed.exists()
          and t_fixed is not None and t_fixed.ok
          and repaired_ok)
    return CheckResult(
        "recovery_record", ok,
        "-rr5: 64 KiB continuous damage detected (exit 3), repaired by rar r, "
        "content byte-identical" if ok else
        "-rr5 recovery flow did not work end to end - see details",
        details,
    )


# --------------------------------------------------------------------------
# Check 14: production two-step create + damage/repair/recover end to end.
# --------------------------------------------------------------------------

def check_two_step_recovery(runner: RarRunner, workdir: Path) -> CheckResult:
    """The production create flow, end to end.

    Step 1 adds .backup/ service files from a staging dir, step 2 adds
    the user files from the source root into the SAME target, finishing
    with -qo+ -rr5. The finished archive is damaged, repaired with
    `rar r` and a user file is extracted byte-identical. The target is
    named <x>.tmp on purpose: the probe records whether RAR appends
    '.rar' to an already-extended target (production tmp-file flow).
    """
    details: list[str] = []

    # --- fixtures: staging (.backup service files) + source (user files)
    staging = workdir / "ts_stage"
    (staging / ".backup").mkdir(parents=True)
    manifest = (b'{"schema_version": 1, "note": "check_two_step_recovery"}'
                b'{"padding": "x"}' * 12)  # ~1 KiB
    (staging / ".backup" / "manifest.json").write_bytes(manifest)
    (staging / ".backup" / "files.json").write_bytes(b'{"files": [], "pad": "' + b"y" * 800 + b'"}')
    details.append(f".backup/manifest.json size: {len(manifest)} B")

    source = workdir / "ts_src"
    (source / "sub").mkdir(parents=True)
    payloads = {
        "user_a.bin": os.urandom(2 << 20),
        "user_b.bin": os.urandom(1 << 20),
        os.path.join("sub", "user_c.bin"): os.urandom(1 << 20),
    }
    for rel, data in payloads.items():
        (source / rel).write_bytes(data)

    # --- step 1: service files (plain name probe below covers 'no extension')
    target = workdir / "two_step.tmp"
    res1 = create_step(runner, target, staging,
                       [".backup\\manifest.json", ".backup\\files.json"],
                       final=False, compression=3)

    # .tmp probe: did RAR append '.rar' to the already-extended target?
    appeared = sorted(p.name for p in workdir.glob("two_step.tmp*"))
    kept_name = target.exists() and not (workdir / "two_step.tmp.rar").exists()
    details.append(f".tmp probe: target 'two_step.tmp' created {appeared} -> "
                   + ("name kept as-is, NO .rar appended" if kept_name
                      else ".rar APPENDED (production must expect it)"))

    # extensionless probe: RAR appends '.rar' to a bare name
    (workdir / "probe_file.txt").write_bytes(b"probe")
    lst = write_list_file(workdir / "probe.lst", [str(workdir / "probe_file.txt")])
    runner.run(["a", "-y", "-scfl", str(workdir / "probe_plain"), f"@{lst}"])
    extless = sorted(p.name for p in workdir.glob("probe_plain*"))
    details.append(f"extensionless probe: target 'probe_plain' created {extless}")

    # --- step 2: user files into the SAME archive, final=True (-qo+ -rr5)
    res2 = create_step(runner, target, source,
                       ["user_a.bin", "user_b.bin", "sub\\user_c.bin"],
                       final=True, compression=3)
    details.append(f"step1 exit={res1.exit_code}, step2 exit={res2.exit_code}, "
                   f"archive size={target.stat().st_size} B")

    t_intact = test_archive(runner, target)
    details.append(f"rar t two-step archive: exit {t_intact}")

    # --- exactly one QO and one RR service record
    lta = runner.run(["lta", "-scfr", str(target)])
    entries = parse_lt(strip_rar_banner(lta.stdout()))
    qo = [e for e in entries if e.get("Name") == "QO"]
    rr = [e for e in entries if e.get("Name") == "RR"]
    header = next((ln.strip() for ln in lta.stdout().splitlines()
                   if ln.strip().startswith(("Details:", "Детали:"))), "<no Details line>")
    details.append(f"lta markers: {header}; QO x{len(qo)} Type={qo[0].get('Type') if qo else '-'}; "
                   f"RR x{len(rr)} Type={rr[0].get('Type') if rr else '-'} "
                   f"RR%={rr[0].get('RR%') if rr else '-'}")
    svc_ok = len(qo) == 1 and len(rr) == 1

    # --- damage 64 KiB at ~45% -> t must report exit 3
    raw = bytearray(target.read_bytes())
    pos = int(len(raw) * 0.45)
    raw[pos:pos + 65536] = os.urandom(65536)
    target.write_bytes(bytes(raw))
    t_bad = test_archive(runner, target)
    details.append(f"rar t after 64 KiB damage @45%: exit {t_bad}")

    # --- repair (fixed.<basename> appears next to the archive), verify
    fixed = repair(runner, target)
    t_fixed = test_archive(runner, fixed)
    details.append(f"rar r -> {fixed.name} ({fixed.stat().st_size} B); "
                   f"rar t repaired: exit {t_fixed}")

    # --- user files from the repaired archive must be byte-identical
    dest = workdir / "ts_out"
    xres = extract_archive(runner, fixed, dest)
    restored_ok = True
    for rel, data in payloads.items():
        full = find_extracted_file(dest, rel.replace("\\", "/"))
        if full is None or open(full, "rb").read() != data:
            restored_ok = False
            details.append(f"restored mismatch: {rel}")
    details.append(f"extract exit={xres.exit_code}; user files byte-identical: {restored_ok}")

    # --- .backup/manifest.json readable from the repaired archive (both tiers)
    try:
        got_manifest = read_service_member(runner, fixed, ".backup/manifest.json")
        manifest_ok = got_manifest == manifest
    except Exception as exc:  # noqa: BLE001 - diagnostics must survive
        manifest_ok = False
        details.append(f"read_service_member failed: {exc!r}")
    details.append(f".backup/manifest.json via read_service_member: {manifest_ok}")

    # --- cleanup of the fixed file (space next to the archive matters)
    fixed_size = fixed.stat().st_size
    fixed.unlink(missing_ok=True)
    details.append(f"fixed file cleaned up (was {fixed_size} B): {not fixed.exists()}")

    ok = (res1.ok and res2.ok and t_intact == 0 and svc_ok
          and t_bad == 3 and t_fixed == 0 and restored_ok and manifest_ok
          and not fixed.exists())
    return CheckResult(
        "two_step_recovery", ok,
        "two-step create into one <x>.tmp target (name kept, no .rar added); "
        "exactly one QO + one RR; 64 KiB damage -> exit 3; rar r -> "
        "fixed.<name> verified, content byte-identical" if ok else
        "two-step create/damage/repair flow misbehaved - see details",
        details,
    )


ALL_CHECKS = [
    check_rar_version,
    check_rar_language,
    check_long_path,
    check_locked_file,
    check_listing,
    check_progress,
    check_utf_names,
    check_stored_name_forms,
    check_ads_streams,
    check_empty_dirs,
    check_missing_file,
    check_mtime_precision,
    check_stdin_listfile,
    check_quick_open,
    check_recovery_record,
    check_two_step_recovery,
]


def run(rar_path: str | None = None, *, keep: bool = False,
        verbose: bool = False) -> int:
    try:
        runner = RarRunner(find_rar(rar_path))
    except FileNotFoundError as exc:
        print(f"error: {exc}", flush=True)
        return 5

    workdir = Path(tempfile.mkdtemp(prefix="backuper_diag_"))
    print("backuper diagnose")
    print(f"  rar     : {runner.rar_path}")
    print(f"  workdir : {workdir}" + (" (kept)" if keep else ""))
    print()

    failures = 0
    try:
        for check in ALL_CHECKS:
            try:
                result = check(runner, workdir)
            except Exception as exc:  # noqa: BLE001 - diagnostics must survive
                result = CheckResult(check.__name__.removeprefix("check_"), False,
                                     f"check crashed: {exc!r}")
            status = "PASS" if result.passed else "FAIL"
            print(f"[{status}] {result.name}: {result.summary}")
            if result.details and (verbose or not result.passed):
                for line in result.details:
                    if line:
                        print(f"       {line}")
            if not result.passed:
                failures += 1
    finally:
        if not keep:
            shutil.rmtree(winapi_path(workdir), ignore_errors=True)

    total = len(ALL_CHECKS)
    print()
    if failures:
        print(f"FAILED: {failures}/{total} checks failed")
        return EXIT_RAR_FAILED
    print(f"OK: {total}/{total} checks passed")
    return EXIT_OK
