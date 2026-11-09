"""Tests for `backuper init`: job directory bootstrap."""

import conftest
import pytest

from backuper.config import load_config
from backuper.errors import ConfigError


def test_init_fresh_dir(tmp_path, capsys):
    job_dir = tmp_path / "job"
    assert conftest.run_cli(["init", str(job_dir)]) == 0
    config_path = job_dir / "config.yaml"
    assert config_path.is_file()
    text = config_path.read_text(encoding="utf-8")
    assert 'source: ""' in text
    assert "created" in capsys.readouterr().out
    # The unedited template must refuse a full run with a clear message.
    with pytest.raises(ConfigError) as ei:
        load_config(config_path)
    assert "source" in str(ei.value)


def test_init_with_source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    job_dir = tmp_path / "job"
    assert conftest.run_cli(["init", str(job_dir), "--source", str(src)]) == 0
    cfg = load_config(job_dir / "config.yaml")
    assert cfg.source == src  # robust against YAML escaping


def test_init_bad_source_exits1(tmp_path, capsys):
    job_dir = tmp_path / "job"
    missing = tmp_path / "nope"
    assert conftest.run_cli(["init", str(job_dir), "--source", str(missing)]) == 1
    assert not job_dir.exists()  # validate-before-write: nothing was created
    assert "does not exist" in capsys.readouterr().err


def test_init_twice_second_fails(tmp_path):
    job_dir = tmp_path / "job"
    assert conftest.run_cli(["init", str(job_dir)]) == 0
    config_path = job_dir / "config.yaml"
    before = config_path.read_bytes()
    assert conftest.run_cli(["init", str(job_dir)]) == 5
    assert config_path.read_bytes() == before  # never overwritten


@pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")
def test_full_refuses_unedited_template(tmp_path):
    job_dir = tmp_path / "job"
    assert conftest.run_cli(["init", str(job_dir)]) == 0
    assert conftest.run_cli(["full", str(job_dir)]) == 5


@pytest.mark.skipif(conftest.RAR_PATH is None, reason="Rar.exe not found")
def test_init_then_full_e2e(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("x", encoding="utf-8")
    job_dir = tmp_path / "job"
    assert conftest.run_cli(["init", str(job_dir), "--source", str(src)]) == 0
    assert conftest.run_cli(["full", str(job_dir)]) == 0
    assert list(job_dir.glob("*/*_full.rar"))
