#!/usr/bin/env python3
"""Bump the project version (single source of truth: backuper/__init__.py).

pyproject.toml reads the version dynamically from backuper/__init__.py
(__version__), so only that file needs editing.

Usage:
  python scripts/bump_version.py --part patch
  python scripts/bump_version.py --part minor
  python scripts/bump_version.py --part major
  python scripts/bump_version.py --set 1.2.3
  python scripts/bump_version.py --part patch --dry-run

Exit code 0 on success, 1 on any validation error. Prints the new version
to stdout.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+].*)?$")
INIT_RE = re.compile(r'^__version__\s*=\s*"([^"]*)"\s*$', re.M)

PARTS = ("none", "patch", "minor", "major")


def read_current(root: Path) -> str:
    init_path = root / "backuper" / "__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    m_init = INIT_RE.search(init_text)
    if not m_init:
        raise ValueError(f"could not find __version__ in {init_path}")
    version = m_init.group(1)
    if not SEMVER_RE.match(version):
        raise ValueError(f"current version is not semver: {version!r}")
    return version


def bump(version: str, part: str) -> str:
    core = version.split("-", 1)[0].split("+", 1)[0]
    major, minor, patch = (int(x) for x in core.split("."))
    if part == "patch":
        patch += 1
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "major":
        major += 1
        minor = 0
        patch = 0
    elif part == "none":
        pass
    else:
        raise ValueError(f"unknown bump part: {part!r}")
    return f"{major}.{minor}.{patch}"


def write_init(root: Path, new_version: str, *, dry_run: bool) -> bool:
    init_path = root / "backuper" / "__init__.py"
    init_text = init_path.read_text(encoding="utf-8")
    new_init = INIT_RE.sub(f'__version__ = "{new_version}"', init_text, count=1)
    if new_init == init_text:
        return False
    if not dry_run:
        init_path.write_text(new_init, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bump project version.")
    parser.add_argument("--part", choices=PARTS, default="patch")
    parser.add_argument("--set", dest="set_version", default=None,
                        help="set an explicit version (overrides --part)")
    parser.add_argument("--root", default=None,
                        help="project root (default: parent of scripts/)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent

    try:
        current = read_current(root)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.set_version is not None:
        if not SEMVER_RE.match(args.set_version):
            print(f"error: invalid version {args.set_version!r}", file=sys.stderr)
            return 1
        new_version = args.set_version
    else:
        try:
            new_version = bump(current, args.part)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    try:
        changed = write_init(root, new_version, dry_run=args.dry_run)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(new_version)
    if args.dry_run:
        print(f"dry-run: would update {int(changed)} file(s)", file=sys.stderr)
    elif changed:
        print(f"updated: {root / 'backuper' / '__init__.py'}", file=sys.stderr)
    else:
        print("no changes (already at target version)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
