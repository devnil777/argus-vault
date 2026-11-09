"""Command line interface git/docker style.

Commands are flat sub-commands of a single entry point::

    python -m backuper init    [<dir>] [--source PATH] [--generate-keys]
    python -m backuper keygen  <dir> [--force]
    python -m backuper full    [<dir>] [--rar PATH] [--signing-private-key PATH]
    python -m backuper diff    [<dir>] [--epoch NAME] [--rar PATH] [--signing-private-key PATH]
    python -m backuper verify  [<dir>] [--epoch NAME] [--chain] [--fix] [--rar PATH] [--recipient-private-key PATH]
    python -m backuper list    [<dir>] [--rar PATH]
    python -m backuper password <archive.rar> [--keys-dir PATH] [--rar PATH] [--recipient-private-key PATH]
    python -m backuper diagnose [--rar PATH] [--keep] [-v]
    python -m backuper schedule add <dir> {diff|full}
        (--daily HH:MM | --weekly DAYS --at HH:MM | --interval MINUTES)
        [--exe PATH] [--rar PATH] [--signing-private-key PATH] [--force] [--no-start-when-available]
    python -m backuper schedule remove <dir> [--kind diff|full|all]
    python -m backuper schedule show [<dir>] [--kind diff|full|all]

``<dir>`` is the backup job directory (default: the current directory).
``keygen`` writes the two private PEM key files next to config.yaml and
records the public keys inside it; ``password`` prints the password of an
encrypted archive (and nothing else) to stdout.

Scheduled tasks run only while the user is logged on and write their output
to <job>\\.schedule.log.

Exit codes follow the project convention:
    0 - success
    1 - preflight failed (rar not found, source missing, bad job dir layout)
    2 - RAR failed (a run failed, a diagnostics check failed, interrupted run)
    3 - verification failed
    4 - job lock held by another backuper process
    5 - config/command line error
    6 - no-op: a diff had nothing to do
  130 - interrupted (Ctrl+C outside the guarded run region)
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

from backuper import __version__
from backuper.errors import BackuperError, NoOpResult


def _add_diagnose_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rar", metavar="PATH", default=None,
                        help="path to Rar.exe (default: search near the script, then PATH)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary diagnostics directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show details for passed checks too")


def _add_dir_and_rar(parser: argparse.ArgumentParser, dir_help: str) -> None:
    parser.add_argument("dir", nargs="?", default=".", metavar="dir", help=dir_help)
    parser.add_argument("--rar", metavar="PATH", default=None,
                        help="path to Rar.exe (default: search near the script, then PATH)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backuper",
        description="RAR-based backup tool with full/diff epoch chains.",
    )
    parser.add_argument("--version", action="version", version=f"backuper {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    init = sub.add_parser("init", help="create a job directory with a config.yaml template")
    init.add_argument("dir", nargs="?", default=".", metavar="dir",
                      help="job directory to create (default: current directory)")
    init.add_argument("--source", metavar="PATH", default=None,
                      help="source directory to write into the config (must exist)")
    init.add_argument("--generate-keys", action="store_true",
                      help="also generate the encryption keypairs (public keys go "
                           "into the config, private PEMs next to it; like 'keygen')")

    keygen = sub.add_parser("keygen",
                            help="generate encryption keypairs for a job directory")
    keygen.add_argument("dir", nargs="?", default=".", metavar="dir",
                        help="job directory with a config.yaml (default: current directory)")
    keygen.add_argument("--force", action="store_true",
                        help="overwrite existing private key files and config keys")

    full = sub.add_parser("full", help="start a new epoch with a full archive")
    _add_dir_and_rar(full, "backup job directory (default: current directory)")
    full.add_argument("--dry-run", action="store_true",
                      help="scan and print statistics without creating an archive")
    full.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    full.add_argument("--signing-private-key", metavar="PATH", default=None,
                      help="path to signing_private.pem (default: next to config.yaml)")

    diff = sub.add_parser("diff", help="append a diff archive to the epoch tip")
    _add_dir_and_rar(diff, "backup job directory (default: current directory)")
    diff.add_argument("--epoch", metavar="NAME", default=None,
                      help="epoch to append to, YYYY-MM-DD (default: the latest)")
    diff.add_argument("--dry-run", action="store_true",
                      help="scan, diff and print statistics without creating an archive")
    diff.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    diff.add_argument("--signing-private-key", metavar="PATH", default=None,
                      help="path to signing_private.pem (default: next to config.yaml)")

    verify = sub.add_parser("verify", help="verify the tip archive or the whole chain")
    _add_dir_and_rar(verify, "backup job directory (default: current directory)")
    verify.add_argument("--epoch", metavar="NAME", default=None,
                        help="epoch to verify, YYYY-MM-DD (default: the latest)")
    verify.add_argument("--chain", action="store_true",
                        help="verify every archive of the epoch incl. chain linkage")
    verify.add_argument("--fix", action="store_true",
                        help="repair damaged archives via the recovery record and "
                             "regenerate drifted sidecars")
    verify.add_argument("--recipient-private-key", metavar="PATH", default=None,
                        help="path to recipient_private.pem")
    lst = sub.add_parser("list", help="list epochs and their archives")
    _add_dir_and_rar(lst, "backup job directory (default: current directory)")

    diag = sub.add_parser("diagnose", help="run RAR self-diagnostics")
    _add_diagnose_args(diag)

    password = sub.add_parser(
        "password", help="print the password of an encrypted archive to stdout")
    password.add_argument("archive", metavar="archive", help="path to the archive (.rar)")
    password.add_argument("--keys-dir", metavar="PATH", default=None,
                          help="job directory holding config.yaml + the private key files "
                               "(default: walk up from the archive's directory)")
    password.add_argument("--rar", metavar="PATH", default=None,
                          help="path to Rar.exe (default: search near the script, then PATH)")
    password.add_argument("--recipient-private-key", metavar="PATH", default=None,
                          help="path to recipient_private.pem")

    schedule = sub.add_parser("schedule", help="manage Windows Task Scheduler jobs")
    sched_sub = schedule.add_subparsers(dest="schedule_action", metavar="<action>")

    sched_add = sched_sub.add_parser("add", help="register a scheduled diff or full run")
    sched_add.add_argument("dir", nargs="?", default=".", metavar="dir",
                           help="backup job directory (default: current directory)")
    sched_add.add_argument("kind", choices=("diff", "full"),
                           help="job kind to schedule")
    when = sched_add.add_mutually_exclusive_group(required=True)
    when.add_argument("--daily", metavar="HH:MM", default=None,
                      help="run every day at this time")
    when.add_argument("--weekly", metavar="DAYS", default=None,
                      help="run on these days, e.g. MON,WED,FRI")
    when.add_argument("--interval", metavar="MINUTES", type=int, default=None,
                      help="run every N minutes")
    sched_add.add_argument("--at", metavar="HH:MM", default=None,
                           help="time of day, required with --weekly")
    sched_add.add_argument("--exe", metavar="PATH", default=None,
                           help="executable to schedule (default: this backuper)")
    sched_add.add_argument("--rar", metavar="PATH", default=None,
                           help="path to Rar.exe (default: search near the script, then PATH)")
    sched_add.add_argument("--signing-private-key", metavar="PATH", default=None,
                           help="path to signing_private.pem")
    sched_add.add_argument("--force", action="store_true",
                           help="overwrite an existing backuper task")
    sched_add.add_argument("--no-start-when-available", action="store_true",
                           help="do not run a missed task once the machine is available")

    sched_remove = sched_sub.add_parser("remove", help="delete scheduled backuper tasks")
    sched_remove.add_argument("dir", nargs="?", default=".", metavar="dir",
                              help="backup job directory (default: current directory)")
    sched_remove.add_argument("--kind", choices=("diff", "full", "all"), default="all",
                              help="task kind to remove (default: all)")

    sched_show = sched_sub.add_parser("show", help="show scheduled backuper tasks")
    sched_show.add_argument("dir", nargs="?", default=None, metavar="dir",
                            help="backup job directory (default: list all backuper tasks)")
    sched_show.add_argument("--kind", choices=("diff", "full", "all"), default="all",
                            help="task kind to show (default: all)")

    return parser


def _print_scheduled_header(command: str) -> None:
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] backuper {command} start")


def _run_schedule(args: argparse.Namespace) -> int:
    """Dispatch the schedule sub-commands."""
    from backuper import scheduler  # noqa: PLC0415 — lazy: startup speed

    if args.schedule_action == "add":
        spec = scheduler.parse_schedule(args.daily, args.weekly, args.at, args.interval)
        name = scheduler.create_task(
            args.dir, args.kind, spec, exe=args.exe, rar=args.rar,
            force=args.force, start_when_available=not args.no_start_when_available,
            signing_private_key=args.signing_private_key)
        print(f"created task {name}")
        print(f"show it with: backuper schedule show {args.dir}")
        return 0
    if args.schedule_action == "remove":
        kinds = scheduler.KINDS if args.kind == "all" else (args.kind,)
        for kind in kinds:
            name = scheduler.task_name(args.dir, kind)
            if scheduler.delete_task(args.dir, kind):
                print(f"removed task {name}")
            else:
                print(f"task {name} not found")
        return 0
    if args.schedule_action == "show":
        kinds = scheduler.KINDS if args.kind == "all" else (args.kind,)
        if args.dir is not None:
            names = [scheduler.task_name(args.dir, kind) for kind in kinds]
        else:
            names = scheduler.list_backuper_tasks()
        if not names:
            print("no backuper tasks found")
            return 0
        for name in names:
            print(f"== {name} ==")
            text = scheduler.query_task(name)
            print("not found" if text is None else text.rstrip())
        return 0
    print(f"error: unknown schedule action: {args.schedule_action}", file=sys.stderr)
    return 5


def _run_command(args: argparse.Namespace) -> int:
    """Dispatch the job commands; translate errors to exit codes.

    runner/diagnose are imported lazily: startup stays fast and a broken
    orchestration layer cannot affect `diagnose`.
    """
    try:
        if args.command == "init":
            from backuper import runner  # noqa: PLC0415 — lazy: startup speed
            return runner.cmd_init(args.dir, args.source, generate_keys=args.generate_keys)
        if args.command == "keygen":
            from backuper import runner  # noqa: PLC0415
            return runner.cmd_keygen(args.dir, force=args.force)
        if args.command == "password":
            from backuper import runner  # noqa: PLC0415
            return runner.cmd_password(
                args.archive, rar_path=args.rar, keys_dir=args.keys_dir,
                recipient_private_key_path=args.recipient_private_key)
        if args.command == "full":
            from backuper import runner  # noqa: PLC0415
            if args.scheduled:
                _print_scheduled_header("full")
            return runner.cmd_full(args.dir, args.rar, dry_run=args.dry_run,
                                   progress=not args.scheduled,
                                   signing_private_key_path=args.signing_private_key)
        if args.command == "diff":
            from backuper import runner  # noqa: PLC0415
            if args.scheduled:
                _print_scheduled_header("diff")
            return runner.cmd_diff(args.dir, args.epoch, args.rar,
                                   dry_run=args.dry_run, progress=not args.scheduled,
                                   signing_private_key_path=args.signing_private_key)
        if args.command == "verify":
            from backuper import runner  # noqa: PLC0415
            return runner.cmd_verify(
                args.dir, args.epoch, chain_mode=args.chain, fix=args.fix, rar_path=args.rar,
                recipient_private_key_path=args.recipient_private_key)
        if args.command == "list":
            from backuper import runner  # noqa: PLC0415
            return runner.cmd_list(args.dir, rar_path=args.rar)
        if args.command == "schedule":
            return _run_schedule(args)
    except NoOpResult as exc:
        print(f"no-op: {exc}")
        return 0 if getattr(args, "scheduled", False) else 6
    except BackuperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    # argparse makes an unknown command unreachable
    print("error: unknown command", file=sys.stderr)
    return 5


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):  # e.g. a closed stream
                pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "diagnose":
        from backuper import diagnose  # noqa: PLC0415 — lazy: startup speed
        return diagnose.run(args.rar, keep=args.keep, verbose=args.verbose)

    if args.command is not None:
        return _run_command(args)

    parser.print_help(sys.stderr)
    return 5
