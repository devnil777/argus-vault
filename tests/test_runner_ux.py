"""Run-status and private-key-presence output without invoking RAR."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from backuper import runner
from backuper.config import (
    CONFIG_NAME,
    RECIPIENT_PRIVATE_NAME,
    SIGNING_PRIVATE_NAME,
    Config,
)
from backuper.models import ENCRYPTION_DATA, Snapshot


def _config(path, source, *, encrypted):
    return Config(
        source=source,
        exclude_extensions=[],
        exclude_dirs=[],
        lock_check_extensions=[],
        compression=3,
        raw_bytes=b"test config",
        path=path,
        recipient_public_pem="recipient public" if encrypted else None,
        signing_public_pem="signing public" if encrypted else None,
        recipient_key_id="recipient-id" if encrypted else None,
        signing_key_id="signing-id" if encrypted else None,
    )


@pytest.mark.parametrize(
    ("present", "expected"),
    [
        ((), ()),
        ((RECIPIENT_PRIVATE_NAME,), (RECIPIENT_PRIVATE_NAME,)),
        ((SIGNING_PRIVATE_NAME,), (SIGNING_PRIVATE_NAME,)),
        ((RECIPIENT_PRIVATE_NAME, SIGNING_PRIVATE_NAME),
         (RECIPIENT_PRIVATE_NAME, SIGNING_PRIVATE_NAME)),
    ],
)
def test_private_key_warning_reports_only_existing_sibling_files(
        tmp_path, capsys, present, expected):
    config_path = tmp_path / CONFIG_NAME
    for name in present:
        (tmp_path / name).write_bytes(b"private")

    runner._warn_private_keys_next_to_config(config_path)

    captured = capsys.readouterr()
    if expected:
        assert "private key file(s) present next to config.yaml" in captured.err
        assert all(name in captured.err for name in expected)
    else:
        assert captured.err == ""
    assert "archive" not in captured.err.lower()
    assert "encrypted" not in captured.err.lower()


@pytest.mark.parametrize("encrypted", [False, True])
def test_full_dry_run_reports_loaded_config_encryption(
        tmp_path, monkeypatch, capsys, encrypted):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    config_path = job_dir / CONFIG_NAME
    config_path.write_text("unused by mocked loader", encoding="utf-8")
    cfg = _config(config_path, source, encrypted=encrypted)

    monkeypatch.setattr(runner, "_resolve_runner", lambda _path: (object(), "test"))
    monkeypatch.setattr(runner, "load_config", lambda _path: cfg)
    monkeypatch.setattr(runner, "_mismatch_warning_for_full", lambda *_args: None)
    monkeypatch.setattr(
        runner, "_scan_phase", lambda *_args: (Snapshot(files=[], empty_dirs=[]), []))

    assert runner.cmd_full(job_dir, None, dry_run=True) == 0

    captured = capsys.readouterr()
    out = captured.out
    if encrypted:
        assert "encryption: ON" in out
    else:
        assert "encryption:" not in out
    assert "file names" not in out
    assert "service metadata" not in out


@pytest.mark.parametrize("operative_encrypted", [False, True])
@pytest.mark.parametrize("has_job_config", [False, True])
def test_diff_dry_run_reports_embedded_config_encryption(
        tmp_path, monkeypatch, capsys, operative_encrypted, has_job_config):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    config_path = job_dir / CONFIG_NAME
    if has_job_config:
        config_path.write_text("job config", encoding="utf-8")
    else:
        (job_dir / RECIPIENT_PRIVATE_NAME).write_bytes(b"presence only")
    epoch_dir = job_dir / "2026-01-01"
    epoch_dir.mkdir()
    full = epoch_dir / "full.rar"
    tip = epoch_dir / "tip.rar"
    base = SimpleNamespace(
        config_bytes=b"embedded config",
        snapshot=Snapshot(files=[], empty_dirs=[]),
        manifest=SimpleNamespace(sources=[str(source)]),
    )
    job_cfg = _config(config_path, source, encrypted=not operative_encrypted)
    operative = _config(Path("<embedded config>"), source,
                        encrypted=operative_encrypted)

    monkeypatch.setattr(runner, "_resolve_runner", lambda _path: (object(), "test"))
    monkeypatch.setattr(runner, "load_config", lambda _path: job_cfg)
    monkeypatch.setattr(runner.chain, "resolve_epoch", lambda *_args: epoch_dir)
    monkeypatch.setattr(runner.chain, "epoch_full", lambda _epoch: full)
    monkeypatch.setattr(runner.chain, "tip_archive", lambda _epoch: tip)
    monkeypatch.setattr(runner.chain, "check_base_archive",
                        lambda *_args, **_kwargs: base)
    monkeypatch.setattr(runner.chain, "config_mismatch_warning", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "config_from_bytes", lambda _data: operative)
    monkeypatch.setattr(runner.diffing, "compute_diff",
                        lambda *_args: SimpleNamespace(is_no_op=True))
    monkeypatch.setattr(
        runner, "_scan_phase", lambda *_args: (Snapshot(files=[], empty_dirs=[]), []))

    assert runner.cmd_diff(job_dir, None, None, dry_run=True) == 0

    captured = capsys.readouterr()
    out = captured.out
    if operative_encrypted:
        assert "encryption: ON" in out
    else:
        assert "encryption:" not in out
    assert "file names" not in out
    assert "service metadata" not in out
    if has_job_config:
        assert RECIPIENT_PRIVATE_NAME not in captured.err
    else:
        assert RECIPIENT_PRIVATE_NAME in captured.err


def test_verify_reports_each_manifest_and_checks_keys_only_next_to_config(
        tmp_path, monkeypatch, capsys):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    epoch_dir = job_dir / "2026-01-01"
    epoch_dir.mkdir()
    archive_dir = epoch_dir / "archives"
    archive_dir.mkdir()
    (archive_dir / RECIPIENT_PRIVATE_NAME).write_bytes(b"not a job key")
    reports = [
        SimpleNamespace(archive=epoch_dir / "full.rar",
                        manifest=SimpleNamespace(encryption=ENCRYPTION_DATA), ok=True),
        SimpleNamespace(archive=epoch_dir / "diff.rar",
                        manifest=SimpleNamespace(encryption=None), ok=True),
    ]

    class _Lock:
        def __init__(self, _job_dir):
            pass

        def acquire(self):
            pass

        def release(self):
            pass

    monkeypatch.setattr(runner, "_resolve_runner", lambda _path: (object(), "test"))
    monkeypatch.setattr(runner.chain, "resolve_epoch", lambda *_args: epoch_dir)
    monkeypatch.setattr(runner, "verify_chain", lambda *_args, **_kwargs: reports)
    monkeypatch.setattr(runner, "print_reports", lambda _reports: None)
    monkeypatch.setattr(runner, "JobLock", _Lock)

    assert runner.cmd_verify(
        job_dir, None, chain_mode=True, fix=False, rar_path=None) == 0
    captured = capsys.readouterr()
    assert "encryption: full.rar: ON" in captured.out
    assert "encryption: diff.rar:" not in captured.out
    assert "file names" not in captured.out
    assert "service metadata" not in captured.out
    assert RECIPIENT_PRIVATE_NAME not in captured.err

    (job_dir / SIGNING_PRIVATE_NAME).write_bytes(b"presence only")
    assert runner.cmd_verify(
        job_dir, None, chain_mode=True, fix=False, rar_path=None) == 0
    assert SIGNING_PRIVATE_NAME in capsys.readouterr().err
