"""Tests for the live phase counter (tty-only, throttled, in-place)."""

import io
import time

from backuper.progress import (
    ArchiveProgress,
    ByteProgress,
    CounterProgress,
    PercentProgress,
    ScanProgress,
)
from backuper.scanner import ScanStats


class FakeTty(io.StringIO):
    def isatty(self) -> bool:  # noqa: N802 - mirrors sys.stdout API
        return True


class FakePipe(io.StringIO):
    def isatty(self) -> bool:  # noqa: N802
        return False


def assert_repaints_never_shrink(out: str) -> None:
    """Every \\r-repaint segment must be at least as long as the previous one."""
    segs = [s for s in out.split("\r") if s]
    for prev, cur in zip(segs, segs[1:], strict=False):
        assert len(cur) >= len(prev), (prev, cur)


def test_tty_repaints_in_place_and_finishes_line():
    stream = FakeTty()
    cp = CounterProgress("scanned", interval=0, stream=stream)  # 0 -> paint all
    for _ in range(3):
        cp.step()
    cp.finish(suffix="done")
    out = stream.getvalue()
    assert "\rscanned 1" in out and "\rscanned 3" in out
    assert out.endswith("scanned 3 done\n")      # finish terminates the line


def test_tty_total_renders_denominator():
    stream = FakeTty()
    cp = CounterProgress("checked", total=10, interval=0, stream=stream)
    cp.report(7)
    cp.finish()
    assert "\rchecked 7/10" in stream.getvalue()


def test_non_tty_is_completely_silent():
    stream = FakePipe()
    cp = CounterProgress("scanned", interval=0, stream=stream)
    for _ in range(5):
        cp.step()
    cp.finish()
    assert stream.getvalue() == ""


def test_throttle_limits_repaints():
    stream = FakeTty()
    cp = CounterProgress("scanned", interval=3600.0, stream=stream)
    for _ in range(1000):
        cp.step()
    cp.finish()                                    # finish repaints unconditionally
    assert stream.getvalue().count("\r") == 2      # one paint + final line


def test_scan_progress_tty_paints_stats_line():
    stream = FakeTty()
    stats = ScanStats(files=10, bytes=2048, dirs=3, files_excluded=2,
                      dirs_excluded=1, links_skipped=2, files_skipped=4)
    sp = ScanProgress(stats, interval=0, stream=stream)
    sp.report()
    sp.finish()
    out = stream.getvalue()
    expected = "  files 10 (2.0 KiB) | dirs 3 | excluded 2f/1d | skipped 4f + 2 links"
    assert "\r" + expected in out
    assert out.endswith("\r")  # finish erases the transient line


def test_scan_progress_non_tty_silent():
    stream = FakePipe()
    stats = ScanStats(files=5)
    sp = ScanProgress(stats, interval=0, stream=stream)
    sp.report()
    sp.finish()
    assert stream.getvalue() == ""


def test_archive_progress_volume_and_file_percent():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=4, cum_bytes=[0, 10, 20, 200, 200],
                         total_bytes=200, interval=0, stream=stream)
    ap(b"Adding  a.bin\r\nAdding  b.bin\r\n")
    assert ap.files_done == 2
    assert ap.percent == 10          # 20 of 200 input bytes
    assert ap.files_percent == 50    # 2 of 4 entries
    ap.finish()
    out = stream.getvalue()
    assert "rar: 10% (20 B/200 B)" in out
    assert "50% (2/4 files)" in out


def test_archive_progress_ignores_rar_percent_tokens():
    # RAR's own NN% rewinds (store fallback); only Adding lines count now.
    ap = ArchiveProgress(total_files=2, cum_bytes=[0, 50, 100], total_bytes=100,
                         interval=0, stream=FakeTty())
    ap(b"5%\r\n80%\r\n30%\r\n")
    assert ap.percent == 0
    ap(b"Adding  a.bin\r\n")
    assert ap.percent == 50


def test_archive_progress_tail_boundary_no_double_count():
    ap = ArchiveProgress(total_files=10, interval=0, stream=FakeTty())
    ap(b"Adding  file_a.txt\r\nAdd")          # "Adding" split across the boundary
    ap(b"ing  file_b.txt\r\n")
    assert ap.files_done == 2                 # counted exactly once each


def test_archive_progress_pipe_silent():
    stream = FakePipe()
    ap = ArchiveProgress(total_files=5, interval=0, stream=stream)
    ap(b"Adding  x.txt\r\n50%\r\n")
    ap.finish()
    assert stream.getvalue() == ""


def test_archive_progress_never_raises_on_garbage():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=1, interval=0, stream=stream)
    ap(b"\xff\xfe garbage \r\x00%%% 1000% Adding")
    ap(b"")
    ap.finish()                               # must not raise anywhere


def test_archive_progress_finish_erases_line():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=10, interval=0, stream=stream)
    ap(b"Adding  a.txt\r\n")
    ap.finish()
    out = stream.getvalue()
    assert out.endswith("\r")                 # transient line erased
    assert "1/10 files" in out


def test_archive_progress_count_only_without_volume_data():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=10, interval=0, stream=stream)
    ap(b"Adding  a.txt\r\n")
    ap.finish()
    out = stream.getvalue()
    assert "10% (1/10 files)" in out
    assert "rar: " not in out


def test_archive_progress_no_signal_fallback_line():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=0, interval=0, stream=stream)
    ap(b"\x00\x01\x02")                       # no percent, no Adding
    ap.finish()
    assert "\r  rar: working ..." in stream.getvalue()


def test_byte_progress_tty_paints_line_and_summary():
    stream = FakeTty()
    bp = ByteProgress("hashing", 100, interval=0, stream=stream)
    bp.started = time.monotonic() - 1.0     # ensure a measurable rate
    bp.report(50)
    bp.finish()
    out = stream.getvalue()
    assert "50%" in out and "100 B" in out and "ETA" in out
    assert "\r" + " " * len(bp._last_line) + "\r" in out    # transient line erased
    assert "  hashing: 50 B in " in out and "/s)" in out    # permanent summary


def test_byte_progress_pipe_prints_only_summary():
    stream = FakePipe()
    bp = ByteProgress("hashing", 100, interval=0, stream=stream)
    bp.report(50)
    assert stream.getvalue() == ""            # live line stays silent in a pipe
    bp.finish()
    out = stream.getvalue()
    assert out.count("\n") == 1 and "in" in out


def test_byte_progress_summary_human_duration():
    stream = FakeTty()
    bp = ByteProgress("hashing", 100, interval=0, stream=stream)
    bp.started = time.monotonic() - 3900.0     # > 1 h
    bp.finish()
    assert "1h 05m" in stream.getvalue()


def test_percent_progress_summary_human_duration():
    stream = FakeTty()
    pp = PercentProgress("rar t", 10, interval=0, stream=stream)
    pp.started = time.monotonic() - 300.0      # 5 minutes
    pp.finish()
    assert "done in 5m 00s" in stream.getvalue()


def test_byte_progress_unknown_total_has_no_percent():
    stream = FakeTty()
    bp = ByteProgress("hashing", 0, interval=0, stream=stream)
    bp.report(42)
    assert "%" not in stream.getvalue()
    bp.finish()
    assert "42 B in " in stream.getvalue()    # summary still printed


def test_byte_progress_double_finish_prints_summary_once():
    stream = FakePipe()
    bp = ByteProgress("hashing", 10, stream=stream)
    bp.finish()
    bp.finish()
    assert stream.getvalue().count("\n") == 1


def test_tester_counts_testing_lines_skips_header():
    stream = FakeTty()
    pp = PercentProgress("rar t", 3, interval=0, stream=stream)
    pp(b"Testing archive C:\\x.rar\r\n"
       b"Testing     a.txt     0%  OK \r\n"
       b"Testing     b.bin    99%  OK \r\n")
    assert pp.files_done == 2                # the "Testing archive" header is not an entry
    assert pp.files_percent == 66            # 2 of 3, floor
    assert "(2/3 files)" in stream.getvalue()
    pp.finish()
    assert "done in" in stream.getvalue()


def test_tester_chunk_boundary_no_double_count():
    stream = FakeTty()
    pp = PercentProgress("rar t", 3, interval=0, stream=stream)
    pp(b"Testing     a.txt\r\nTesting     b.")
    pp(b"bin OK \r\nTesting     c.ini OK \r\n")
    assert pp.files_done == 3                # the split "Testing" counted once


def test_tester_no_percent_token_parsing():
    stream = FakeTty()
    pp = PercentProgress("rar t", 2, interval=0, stream=stream)
    pp(b"Testing     f.bin    45% 80% 30%  OK \r\n")
    assert pp.files_done == 1 and pp.files_percent == 50
    assert pp.percent == 0                   # per-file NN% tokens are ignored


def test_tester_volume_percent_and_files_eta():
    stream = FakeTty()
    mib = 1024 * 1024
    pp = PercentProgress("rar t", 2, cum_bytes=[0, 90 * mib, 100 * mib],
                         total_bytes=100 * mib, interval=0, stream=stream)
    pp.started = time.monotonic() - 10.0
    pp(b"Testing     big.bin  OK \r\n")
    out = stream.getvalue()
    assert "90% (90.0 MiB/100.0 MiB)" in out
    assert "50% (1/2 files)" in out
    assert "ETA" in out and "files/s" in out


def test_tester_working_line_on_first_paint():
    stream = FakeTty()
    pp = PercentProgress("rar t", 10, interval=0, stream=stream)
    pp.report()
    assert "  rar t: working ..." in stream.getvalue()
    assert "ETA" not in stream.getvalue()


def test_tester_pipe_silent_until_summary():
    stream = FakePipe()
    pp = PercentProgress("rar t", 5, interval=0, stream=stream)
    pp(b"Testing     a.txt  OK \r\n")
    assert stream.getvalue() == ""           # live line stays silent in a pipe
    pp.finish()
    assert "done in" in stream.getvalue()


def test_tester_never_raises_on_garbage():
    stream = FakeTty()
    pp = PercentProgress("rar t", 2, interval=0, stream=stream)
    pp(b"\xff\xfe %%$1000% \x00garbage testing")
    pp(b"")
    pp.finish()                               # must not raise anywhere
    assert pp.files_done == 0 and pp.percent == 0


def test_tester_counts_per_chunked_stream():
    stream = FakeTty()
    pp = PercentProgress("rar t", 4, interval=0, stream=stream)
    for name in ("a", "b", "c", "d"):
        pp(b"Testing     " + name.encode() + b".txt  OK \r\n")
    assert pp.files_done == 4 and pp.files_percent == 100


def test_archive_progress_eta_after_slow_chunk():
    stream = FakeTty()
    mib = 1024 * 1024
    ap = ArchiveProgress(total_files=2, cum_bytes=[0, 50 * mib, 100 * mib],
                         total_bytes=100 * mib, interval=0, stream=stream)
    ap(b"Adding  a.bin\r\n")
    ap._started = time.monotonic() - 10.0
    ap.report()
    out = stream.getvalue()
    assert "files/s" in out and "ETA" in out
    assert "MiB/s" not in out


def test_archive_progress_no_eta_without_file_progress():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=10, cum_bytes=[0] * 11, total_bytes=0,
                         interval=0, stream=stream)
    ap._started = time.monotonic() - 10.0
    ap.report()
    out = stream.getvalue()
    assert "files/s" not in out
    assert "ETA" not in out


def test_archive_progress_eta_pipe_stays_silent():
    stream = FakePipe()
    mib = 1024 * 1024
    ap = ArchiveProgress(total_files=2, cum_bytes=[0, 50 * mib, 100 * mib],
                         total_bytes=100 * mib, interval=0, stream=stream)
    ap(b"Adding  a.bin\r\n")
    ap._started = time.monotonic() - 10.0
    ap.report()
    ap.finish()
    assert stream.getvalue() == ""


def test_counter_progress_repaint_pads_shorter_line():
    stream = FakeTty()
    cp = CounterProgress("scanned", total=1000, interval=0, stream=stream)
    cp.report(999)
    cp.report(1)
    out = stream.getvalue()
    assert out.endswith(
        "\rscanned 1/1000"
        + " " * (len("scanned 999/1000") - len("scanned 1/1000")))
    assert_repaints_never_shrink(out)


def test_byte_progress_repaint_pads_shorter_line():
    stream = FakeTty()
    bp = ByteProgress("sha256", 1000, interval=0, stream=stream)
    bp.started = time.monotonic() - 2.0     # long line: high rate + ETA
    bp.report(900)
    bp.started = time.monotonic()           # shorten the line (no rate)
    bp.report(5)
    assert bp._width == max(len(line) for line in
                            stream.getvalue().split("\r") if line.strip())
    assert_repaints_never_shrink(stream.getvalue())


def test_percent_progress_repaint_pads_shorter_line():
    stream = FakeTty()
    pp = PercentProgress("rar t", 100, interval=0, stream=stream)
    pp.started = time.monotonic() - 10.0    # long line: rate + ETA
    pp(b"Testing     f01.bin  OK \r\n")
    pp.started = time.monotonic()           # ETA/rate gone -> shorter line
    pp.report()
    assert_repaints_never_shrink(stream.getvalue())


def test_archive_progress_finish_erases_widest_line():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=2, cum_bytes=[0, 50, 100], total_bytes=100,
                         interval=0, stream=stream)
    ap(b"Adding  a.bin\r\n")
    ap._started = time.monotonic() - 10.0   # long line: rate + ETA
    ap.report()
    widest = ap._width
    ap._started = time.monotonic()          # next line is shorter
    ap.report()
    assert ap._width == widest              # width never goes backwards
    ap.finish()
    out = stream.getvalue()
    assert f"\r{' ' * widest}\r" in out     # erase uses the widest width



def test_archive_progress_russian_markers():
    stream = FakeTty()
    ap = ArchiveProgress(total_files=2, cum_bytes=[0, 5, 10], total_bytes=10,
                        interval=0, stream=stream)
    ap("Добавление  a.bin\r\nОбновление  b.bin\r\n".encode())
    assert ap.files_done == 2
    assert ap.percent == 100


def test_archive_progress_russian_tail_boundary():
    ap = ArchiveProgress(total_files=2, interval=0, stream=FakeTty())
    ap("Добавле".encode())
    ap("ние  a.bin\r\n".encode())
    assert ap.files_done == 1


def test_percent_progress_russian_markers():
    stream = FakeTty()
    pp = PercentProgress("rar t", 2, interval=0, stream=stream)
    pp("Тестирование  a.bin  OK \r\nТестирование  b.bin  OK \r\n".encode())
    assert pp.files_done == 2


def test_percent_progress_russian_header_not_counted():
    pp = PercentProgress("rar t", 2, interval=0, stream=FakeTty())
    pp("Тестирование архива  x.rar\r\nТестирование  a.bin  OK \r\n".encode())
    assert pp.files_done == 1
