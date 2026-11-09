"""Unit tests for backuper.config: loading, normalization, error matrix."""

import pytest

from backuper.config import (
    ConfigError,
    config_from_bytes,
    load_config,
    normalize_exclude_dir,
    normalize_ext,
    semantic_key,
)


def write_cfg(dir_path, text, name="config.yaml"):
    p = dir_path / name
    p.write_bytes(text.encode("utf-8"))
    return p


def test_load_config_happy_path_and_normalization(tmp_path):
    src = tmp_path / "data"
    src.mkdir()
    p = write_cfg(tmp_path, (
        f"source: {src.as_posix()}\n"
        "exclude_extensions: [TMP, .Bak, '  tmp2  ']\n"
        "exclude_dirs: ['/Node_Modules/', 'Stuff']\n"
        "lock_check_extensions: [PST]\n"
        "compression: 5\n"
    ))
    cfg = load_config(p)
    assert cfg.source == src
    assert cfg.exclude_extensions == [".tmp", ".bak", ".tmp2"]
    assert cfg.exclude_dirs == ["node_modules", "stuff"]
    assert cfg.lock_check_extensions == [".pst"]
    assert cfg.compression == 5
    assert cfg.raw_bytes == p.read_bytes()
    assert cfg.path == p


def test_load_config_defaults(tmp_path):
    p = write_cfg(tmp_path, "source: C:/x\n")
    cfg = load_config(p)
    assert cfg.compression == 3
    assert cfg.exclude_extensions == []
    assert cfg.exclude_dirs == []
    assert cfg.lock_check_extensions == []


def test_config_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "absent.yaml")


def test_config_invalid_yaml(tmp_path):
    p = write_cfg(tmp_path, "source: [unclosed\n  - x\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_config_not_valid_utf8(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_bytes(b"source: C:/\xff\xfe x\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_config_unknown_key(tmp_path):
    p = write_cfg(tmp_path, "source: C:/x\nexclude_extention: ['.tmp']\n")
    with pytest.raises(ConfigError) as ei:
        load_config(p)
    assert "unknown key" in str(ei.value)


def test_config_bad_compression(tmp_path):
    for val in ("6", "-1", "'fast'", "true", "3.5"):
        p = write_cfg(tmp_path, f"source: C:/x\ncompression: {val}\n")
        with pytest.raises(ConfigError):
            load_config(p)


def test_config_missing_or_relative_source(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "exclude_extensions: []\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: relative/dir\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: '   '\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: ''\n"))


def test_config_other_rejections(tmp_path):
    # top level not a mapping
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "- a\n- b\n"))
    # non-string key
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "1: x\n"))
    # list fields with wrong shapes
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: C:/x\nexclude_extensions: 'tmp'\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: C:/x\nexclude_extensions: [1]\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: C:/x\nexclude_extensions: ['']\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: C:/x\nlock_check_extensions: {a: 1}\n"))
    with pytest.raises(ConfigError):
        load_config(write_cfg(tmp_path, "source: C:/x\nexclude_dirs:\n  - ok\n  - 2\n"))


def test_config_from_bytes_matches_load_config(tmp_path):
    src = tmp_path / "d"
    src.mkdir()
    text = f"source: {src.as_posix()}\ncompression: 1\nexclude_extensions: ['.tmp']\n"
    raw = text.encode("utf-8")
    a = load_config(write_cfg(tmp_path, text))
    b = config_from_bytes(raw)
    assert semantic_key(a) == semantic_key(b)
    assert a.source == b.source
    assert a.exclude_extensions == b.exclude_extensions
    assert a.compression == b.compression
    assert b.raw_bytes == raw
    # same validation rules -> same errors
    with pytest.raises(ConfigError):
        config_from_bytes(b"unknown_key: 1\n")
    with pytest.raises(ConfigError):
        config_from_bytes(b"source: [unclosed\n")
    with pytest.raises(ConfigError):
        config_from_bytes(b"source: relative/dir\n")
    with pytest.raises(ConfigError):
        config_from_bytes(b"")


def test_config_from_bytes_embed_rehash_roundtrip():
    raw = b"source: C:/Data\nexclude_extensions: ['.tmp']\n"
    cfg = config_from_bytes(raw)
    again = config_from_bytes(cfg.raw_bytes)
    assert again.raw_bytes == raw
    assert semantic_key(again) == semantic_key(cfg)


def test_semantic_key_stable_across_bom_crlf_reorder():
    base = "source: C:/Data\nexclude_extensions: ['.tmp']\ncompression: 2\n"
    a = config_from_bytes(base.encode("utf-8"))
    variant = (
        "\ufeffcompression: 2\r\n"           # BOM + CRLF
        "exclude_extensions: ['.tmp']\r\n"
        "source: C:/Data\r\n"
    )
    b = config_from_bytes(variant.encode("utf-8"))
    assert semantic_key(a) == semantic_key(b)


def test_semantic_key_detects_real_changes():
    a = config_from_bytes(b"source: C:/Data\ncompression: 2\n")
    assert semantic_key(a) != semantic_key(config_from_bytes(b"source: C:/Other\ncompression: 2\n"))
    assert semantic_key(a) != semantic_key(config_from_bytes(b"source: C:/Data\ncompression: 3\n"))
    other = config_from_bytes(
        b"source: C:/Data\ncompression: 2\nexclude_dirs: ['x']\n"
    )
    assert semantic_key(a) != semantic_key(other)


def test_normalize_ext():
    assert normalize_ext("TMP") == ".tmp"
    assert normalize_ext(" .PST ") == ".pst"
    assert normalize_ext(".tmp") == ".tmp"
    assert normalize_ext("") == ""
    assert normalize_ext("   ") == ""


@pytest.mark.parametrize("path", [
    "C:/Data/Documents/",
    "C:\\Data\\Documents\\",
    r"c:\DATA\documents",
])
def test_normalize_exclude_dir_absolute_drive_path(path):
    assert normalize_exclude_dir(path) == r"c:\data\documents"


def test_normalize_exclude_dir_preserves_drive_root_as_absolute():
    assert normalize_exclude_dir("D:\\") == "d:\\"


def test_normalize_exclude_dir_unc_and_extended_paths():
    assert normalize_exclude_dir(r"//Server/Share/Folder/") == r"\\server\share\folder"
    assert normalize_exclude_dir("\\\\?\\UNC\\Server\\Share\\Folder\\") == (
        r"\\server\share\folder")
    assert normalize_exclude_dir("\\\\?\\C:\\Data\\Folder\\") == r"c:\data\folder"


def test_normalize_exclude_dir_bare_name_keeps_legacy_behavior():
    assert normalize_exclude_dir("/Node_Modules/") == "node_modules"


def test_semantic_key_normalizes_equivalent_absolute_exclude_dirs():
    slash = config_from_bytes(
        b"source: 'C:/Data'\nexclude_dirs: ['C:/Data/Cache/']\n")
    backslash = config_from_bytes(
        b"source: 'C:/Data'\nexclude_dirs: ['c:\\data\\cache']\n")
    assert slash.exclude_dirs == [r"c:\data\cache"]
    assert semantic_key(slash) == semantic_key(backslash)
