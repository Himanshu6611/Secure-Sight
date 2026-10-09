"""Security contract for deployment secret-file loading."""
import os

import pytest

from app.core.secrets import runtime_secret


def test_runtime_secret_reads_trimmed_file_and_does_not_mutate_environment(tmp_path, monkeypatch):
    secret_file = tmp_path / "key"
    secret_file.write_text("  independently-generated-secret\n", encoding="utf8")
    monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(secret_file))

    assert runtime_secret("EXAMPLE_SECRET") == "independently-generated-secret"
    assert "EXAMPLE_SECRET" not in os.environ


@pytest.mark.parametrize("contents", ["", " \n", "key\nnext", "key\rnext", "key\x00tail"])
def test_runtime_secret_rejects_empty_or_multiline_file(tmp_path, monkeypatch, contents):
    secret_file = tmp_path / "key"
    secret_file.write_text(contents, encoding="utf8")
    monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(secret_file))

    with pytest.raises(ValueError, match="Runtime secret file unavailable or invalid"):
        runtime_secret("EXAMPLE_SECRET")


def test_runtime_secret_rejects_oversized_file(tmp_path, monkeypatch):
    secret_file = tmp_path / "key"
    secret_file.write_bytes(b"x" * 8193)
    monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(secret_file))

    with pytest.raises(ValueError, match="Runtime secret file unavailable or invalid"):
        runtime_secret("EXAMPLE_SECRET")


def test_runtime_secret_rejects_conflicting_direct_and_file_values(tmp_path, monkeypatch):
    secret_file = tmp_path / "key"
    secret_file.write_text("file-secret", encoding="utf8")
    monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("EXAMPLE_SECRET", "direct-secret")

    with pytest.raises(ValueError, match="Conflicting runtime secret configuration"):
        runtime_secret("EXAMPLE_SECRET")
