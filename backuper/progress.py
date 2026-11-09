"""Live phase progress indicator.

A tiny in-place counter for long-running phases: repaints
``\\r<label> 123[/total]`` at most ``interval`` times per second. Tty-only —
under redirection/CI (and in the run logs) it stays completely silent, the
phase-start lines and the final summaries carry the information there.

The byte/percent trackers (:class:`ByteProgress`, :class:`PercentProgress`)
keep the same tty-only live line but always print one permanent summary line,
also when redirected, so the run log records duration and throughput.
"""

from __future__ import annotations

import re
import sys
import time


class CounterProgress:
    """Monotonic counter with throttled, in-place terminal repaint.

    ``step(n)``/``report(done)`` are cheap (a monotonic-time check per call
    when the throttle hides the repaint) and safe to call from a hot loop.
    """

    def __init__(self, label: str, *, total: int | None = None,
                 interval: float = 0.2, stream=None) -> None:
        self.label = label
        self.total = total
        self.interval = interval
        self.stream = stream if stream is not None else sys.stdout
        self.count = 0
        self._last_paint = 0.0
        self._painted = False
        self._width = 0

    @property
    def _active(self) -> bool:
        try:
            return self.stream.isatty()
        except (AttributeError, ValueError):
            return False

    def step(self, n: int = 1) -> None:
        self.report(self.count + n)

    def report(self, done: int) -> None:
        self.count = done
        if not self._active:
            return
        now = time.monotonic()
        if self._painted and now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._painted = True
        total = f"/{self.total}" if self.total is not None else ""
        line = f"{self.label} {self.count}{total}"
        self._width = _paint(self.stream, line, self._width)

    def finish(self, suffix: str = "") -> None:
        """Repaint the final value once and terminate the line.

        No-op unless something was painted (tty and at least one call).
        """
        if not self._active or not self._painted:
            return
        self._last_paint = 0.0
        total = f"/{self.total}" if self.total is not None else ""
        tail = f" {suffix}" if suffix else ""
        text = f"{self.label} {self.count}{total}{tail}"
        pad = max(0, self._width - len(text))
        print(f"\r{text}{' ' * pad}", file=self.stream, flush=True)


def _fmt_bytes(num: int) -> str:
    size = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"  # unreachable


def fmt_duration(seconds: float) -> str:
    """Compact human duration: ``1h 05m`` / ``3m 07s`` / ``12.4s``."""
    if seconds >= 3600.0:
        return f"{int(seconds // 3600)}h {int(seconds % 3600 // 60):02d}m"
    if seconds >= 60.0:
        return f"{int(seconds // 60)}m {int(seconds % 60):02d}s"
    return f"{seconds:.1f}s"


def _fmt_rate(bytes_done: int, seconds: float) -> str:
    """Throughput like ``12.3 MiB/s``; empty when no time has elapsed yet."""
    if seconds > 0:
        return f"{_fmt_bytes(int(bytes_done / seconds))}/s"
    return ""


def _paint(stream, line: str, width: int) -> int:
    """Repaint an in-place line; blanks the leftover tail of the previous one."""
    pad = max(0, width - len(line))
    print(f"\r{line}{' ' * pad}", end="", file=stream, flush=True)
    return max(width, len(line))


def _erase(stream, width: int) -> None:
    """Blank a previously painted in-place line and return the cursor."""
    print(f"\r{' ' * width}\r", end="", file=stream, flush=True)


class ScanProgress:
    """Live scan counter: repaints the whole ScanStats line in place.

    Fed by scanner.scan_source after every visited entry; the throttle (and
    the tty check) live here, so the callback itself stays cheap. Silent
    under redirection — the final `scan: ...` block carries the numbers.
    """

    def __init__(self, stats, *, interval: float = 0.2, stream=None) -> None:
        self.stats = stats
        self.interval = interval
        self.stream = stream if stream is not None else sys.stdout
        self._last_paint = 0.0
        self._painted = False
        self._width = 0

    @property
    def _active(self) -> bool:
        try:
            return self.stream.isatty()
        except (AttributeError, ValueError):
            return False

    def _line(self) -> str:
        s = self.stats
        return (f"  files {s.files} ({_fmt_bytes(s.bytes)}) | dirs {s.dirs} | "
                f"excluded {s.files_excluded}f/{s.dirs_excluded}d | "
                f"skipped {s.files_skipped}f + {s.links_skipped} links")

    def report(self) -> None:
        if not self._active:
            return
        now = time.monotonic()
        if self._painted and now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._painted = True
        self._width = _paint(self.stream, self._line(), self._width)

    def finish(self) -> None:
        """Terminate the in-place line; no-op when nothing was painted."""
        if not self._active or not self._painted:
            return
        _erase(self.stream, self._width)


class ArchiveProgress:
    """Live archive-creation indicator fed by RAR stdout chunks.

    Passed to :func:`rar_runner.create_step` as ``progress_callback`` (invoked
    from the rar stdout pump thread). Parses ``Adding`` lines with a 64-byte
    rolling tail so matches split across 64 KiB chunk boundaries are seen
    exactly once: one line per stored entry (including empty dirs), emitted in
    listfile order, so ``files_done`` tracks position in that list.

    RAR's own ``NN%`` indicator is deliberately ignored: it rewinds — RAR
    restarts it on the store-fallback second pass (see DIAGNOSTICS #16) — so a
    monotonic max latches a stale peak. Both percentages are computed here
    instead, from the list order plus the snapshot sizes supplied by the
    caller as ``cum_bytes`` (prefix sums of input bytes per listfile entry,
    dirs last and contributing 0 bytes):

    - volume percent = input bytes of the started entries / total input bytes;
    - file percent = ``files_done`` / ``total_files``.

    Throughput and ETA are derived from the file count only
    (``files_done / elapsed``): no byte-based rate and no RAR percent parsing
    is done.

    Repaints one in-place line, throttled, tty-only; a missing signal is
    omitted from the line. Silent under redirection — the OK summary and the
    run log carry the numbers there. Never raises: an exception escaping
    into the pump thread would fail the rar run even if RAR itself won.
    """

    def __init__(self, total_files: int, *, cum_bytes: list[int] | None = None,
                 total_bytes: int = 0, interval: float = 0.2, stream=None) -> None:
        self._adding_re = re.compile(
            "(?:Adding|Updating|"
            "\u0414\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0438\u0435|"
            "\u041e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435)"
            .encode()
        )
        self.total_files = total_files
        self.cum_bytes = cum_bytes
        self.total_bytes = total_bytes
        self.interval = interval
        self.stream = stream if stream is not None else sys.stdout
        self.percent = 0
        self.files_done = 0
        self._tail = b""
        self._stream_len = 0   # total stream bytes fed so far
        self._adding_pos = 0   # global offset up to which Adding was counted
        self._started: float | None = None
        self._last_paint = 0.0
        self._painted = False
        self._last_line = ""
        self._finished = False
        self._width = 0

    @property
    def files_percent(self) -> int:
        return min(100, self.files_done * 100 // self.total_files) if self.total_files else 0

    @property
    def _active(self) -> bool:
        try:
            return self.stream.isatty()
        except (AttributeError, ValueError):
            return False

    def _elapsed(self) -> float:
        if self._started is None:
            return 0.0
        return max(0.0, time.monotonic() - self._started)

    def _line(self) -> str:
        parts = []
        elapsed = self._elapsed()
        has_volume = bool(self.cum_bytes) and self.total_bytes > 0
        if has_volume:
            i = min(self.files_done, len(self.cum_bytes) - 1)
            done = self.cum_bytes[i]
            parts.append(f"rar: {self.percent}% "
                         f"({_fmt_bytes(done)}/{_fmt_bytes(self.total_bytes)})")
        if self.total_files:
            parts.append(f"{self.files_percent}% "
                         f"({self.files_done}/{self.total_files} files)")
            if elapsed > 0.5 and self.files_done > 0:
                per_sec = self.files_done / elapsed
                parts.append(f"{per_sec:.1f} files/s")
                remaining_files = self.total_files - self.files_done
                if remaining_files > 0:
                    parts.append(f"ETA {fmt_duration(remaining_files / per_sec)}")
        return "  " + " | ".join(parts) if parts else "  rar: working ..."

    def __call__(self, chunk: bytes) -> None:
        try:
            self._feed(chunk)
        except Exception:  # noqa: BLE001 — progress must never kill a rar run
            pass

    def _feed(self, chunk: bytes) -> None:
        if not chunk or not self._active:
            return
        if self._started is None:
            self._started = time.monotonic()
        data = self._tail + chunk
        # Global offset of data[0]: the tail overlaps the previous chunk, so
        # match positions are tracked in stream coordinates and a match is
        # counted once even when its text spans a chunk boundary.
        base = self._stream_len - len(self._tail)
        for m in self._adding_re.finditer(data):
            gend = base + m.end()
            if gend > self._adding_pos:
                self.files_done += 1
                self._adding_pos = gend
        if self.cum_bytes and self.total_bytes > 0:
            i = min(self.files_done, len(self.cum_bytes) - 1)
            pct = self.cum_bytes[i] * 100 // self.total_bytes
            if pct > self.percent:      # clamp: never go backwards
                self.percent = pct
        self._stream_len += len(chunk)
        self._tail = data[-64:]
        self.report()

    def report(self) -> None:
        if self._started is None:
            self._started = time.monotonic()
        if not self._active:
            return
        now = time.monotonic()
        if self._painted and now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._painted = True
        self._last_line = self._line()
        self._width = _paint(self.stream, self._last_line, self._width)

    def finish(self) -> None:
        """Erase the in-place line; no-op when nothing was painted."""
        if self._finished:
            return
        self._finished = True
        if not self._active or not self._painted:
            return
        _erase(self.stream, self._width)


class ByteProgress:
    """Live byte counter for long single-file I/O (sha256 hashing).

    ``report(done)`` is called from the hashing loop with the bytes consumed
    so far; the line shows percent, bytes, throughput and ETA, throttled and
    tty-only. ``finish()`` always prints one permanent summary line — also
    under redirection — so the run log keeps duration and throughput.
    """

    def __init__(self, label: str, total: int, *, interval: float = 0.2,
                 stream=None) -> None:
        self.label = label
        self.total = total
        self.interval = interval
        self.stream = stream if stream is not None else sys.stdout
        self.done = 0
        self.started = time.monotonic()
        self._last_paint = 0.0
        self._painted = False
        self._last_line = ""
        self._finished = False
        self._width = 0

    @property
    def _active(self) -> bool:
        try:
            return self.stream.isatty()
        except (AttributeError, ValueError):
            return False

    def _elapsed(self) -> float:
        return max(0.0, time.monotonic() - self.started)

    def _line(self) -> str:
        elapsed = self._elapsed()
        if self.total > 0:
            pct = min(100, self.done * 100 // self.total)
            line = (f"  {self.label}: {pct}% "
                    f"({_fmt_bytes(self.done)}/{_fmt_bytes(self.total)})")
        else:
            line = f"  {self.label}: {_fmt_bytes(self.done)}"
        rate = _fmt_rate(self.done, elapsed)
        if rate:
            line += f" | {rate}"
            speed = self.done / elapsed if elapsed > 0 else 0.0
            if speed > 0 and self.done < self.total:
                line += f" | ETA {fmt_duration((self.total - self.done) / speed)}"
        return line

    def report(self, done: int) -> None:
        self.done = done
        if not self._active:
            return
        now = time.monotonic()
        if self._painted and now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._painted = True
        self._last_line = self._line()
        self._width = _paint(self.stream, self._last_line, self._width)

    def finish(self) -> None:
        """Erase the live line and print the permanent summary (always)."""
        if self._finished:
            return
        self._finished = True
        elapsed = self._elapsed()
        if self._active and self._painted:
            _erase(self.stream, self._width)
        rate = _fmt_rate(self.done, elapsed)
        tail = f" ({rate})" if rate else ""
        print(f"  {self.label}: {_fmt_bytes(self.done)} in {fmt_duration(elapsed)}{tail}",
              file=self.stream, flush=True)


class PercentProgress:
    """Live progress indicator for ``rar t`` fed by raw stdout chunks.

    Same design as :class:`ArchiveProgress` (the create step): RAR's own
    ``NN%`` tokens are IGNORED — during ``t`` they are per-FILE progress
    (they rewind on every new entry, and a monotonic max would latch a
    stale peak). Instead, ``Testing`` lines are counted with a rolling
    tail so matches split across chunk boundaries are seen exactly once;
    the entry count plus the OPTIONAL totals supplied by the caller
    (``total_files``, and ``cum_bytes``/``total_bytes`` — prefix sums of
    entry sizes in archive order, e.g. from a listing) drive:

    - volume percent = started-entry bytes / total entry bytes;
    - entry percent = ``files_done`` / ``total_files``;
    - throughput + ETA from the entry count only (``files_done / elapsed``).

    Without totals the line is a plain counter. Never raises: an exception
    escaping into the pump thread would fail the run even if RAR itself
    won. ``finish()`` always prints one permanent summary line, also under
    redirection.
    """

    def __init__(
        self,
        label: str = "rar t",
        total_files: int = 0,
        *,
        cum_bytes: list[int] | None = None,
        total_bytes: int = 0,
        interval: float = 0.2,
        stream=None,
    ) -> None:
        self.label = label
        self.total_files = total_files
        self.cum_bytes = cum_bytes
        self.total_bytes = total_bytes
        self.interval = interval
        self.stream = stream if stream is not None else sys.stdout
        self.percent = 0
        self.files_done = 0
        self.started = time.monotonic()
        self._testing_re = re.compile(
            "(?:Testing(?! archive)|"
            "\u0422\u0435\u0441\u0442\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435(?! "
            "\u0430\u0440\u0445\u0438\u0432\u0430))"
            .encode()
        )
        self._tail = b""
        self._stream_len = 0   # total stream bytes fed so far
        self._testing_pos = 0  # global offset up to which Testing was counted
        self._last_paint = 0.0
        self._painted = False
        self._last_line = ""
        self._finished = False
        self._width = 0

    @property
    def files_percent(self) -> int:
        return (min(100, self.files_done * 100 // self.total_files)
                if self.total_files else 0)

    @property
    def _active(self) -> bool:
        try:
            return self.stream.isatty()
        except (AttributeError, ValueError):
            return False

    def _elapsed(self) -> float:
        return max(0.0, time.monotonic() - self.started)

    def _line(self) -> str:
        parts = []
        elapsed = self._elapsed()
        has_volume = bool(self.cum_bytes) and self.total_bytes > 0
        if self.files_done == 0:
            return f"  {self.label}: working ..."
        if has_volume:
            i = min(self.files_done, len(self.cum_bytes) - 1)
            done = self.cum_bytes[i]
            parts.append(f"{self.label}: {self.percent}% "
                         f"({_fmt_bytes(done)}/{_fmt_bytes(self.total_bytes)})")
        if self.total_files:
            parts.append(f"{self.files_percent}% "
                         f"({self.files_done}/{self.total_files} files)")
            if elapsed > 0.5 and self.files_done > 0:
                per_sec = self.files_done / elapsed
                parts.append(f"{per_sec:.1f} files/s")
                remaining_files = self.total_files - self.files_done
                if remaining_files > 0:
                    parts.append(f"ETA {fmt_duration(remaining_files / per_sec)}")
        return "  " + " | ".join(parts)

    def __call__(self, chunk: bytes) -> None:
        try:
            self._feed(chunk)
        except Exception:  # noqa: BLE001 — progress must never kill a rar run
            pass

    def _feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        data = self._tail + chunk
        # Global offset of data[0]: the tail overlaps the previous chunk, so
        # match positions are tracked in stream coordinates and a match is
        # counted once even when its text spans a chunk boundary.
        base = self._stream_len - len(self._tail)
        for m in self._testing_re.finditer(data):
            gend = base + m.end()
            if gend > self._testing_pos:
                self.files_done += 1
                self._testing_pos = gend
        self._stream_len += len(chunk)
        self._tail = data[-64:]
        if self.cum_bytes and self.total_bytes > 0:
            i = min(self.files_done, len(self.cum_bytes) - 1)
            pct = self.cum_bytes[i] * 100 // self.total_bytes
            if pct > self.percent:      # clamp: never go backwards
                self.percent = pct
        self.report()

    def report(self) -> None:
        if not self._active:
            return
        now = time.monotonic()
        if self._painted and now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._painted = True
        self._last_line = self._line()
        self._width = _paint(self.stream, self._last_line, self._width)

    def finish(self) -> None:
        """Erase the live line and print the permanent summary (always)."""
        if self._finished:
            return
        self._finished = True
        if self._active and self._painted:
            _erase(self.stream, self._width)
        print(f"  {self.label}: done in {fmt_duration(self._elapsed())}",
              file=self.stream, flush=True)
