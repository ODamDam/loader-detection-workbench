import os
from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.report import service as report_module
from loader_detection_workbench.report.service import write_report


def test_publish_complete_utf8_and_create_parent(tmp_path: Path) -> None:
    output = tmp_path / "reports" / "demo.md"
    write_report(output, "# 보고서\ncomplete\n")
    assert output.read_bytes() == "# 보고서\ncomplete\n".encode()
    assert not list(output.parent.glob(".report-*.tmp"))


@pytest.mark.parametrize("mode", ["file", "directory"])
def test_existing_output_never_overwritten(tmp_path: Path, mode: str) -> None:
    output = tmp_path / "report.md"
    if mode == "file":
        output.write_bytes(b"original")
    else:
        output.mkdir()
    with pytest.raises(DomainError) as caught:
        write_report(output, "new")
    assert caught.value.code is DomainErrorCode.REPORT_OUTPUT_EXISTS
    if mode == "file":
        assert output.read_bytes() == b"original"
    assert not list(tmp_path.glob(".report-*.tmp"))


@pytest.mark.parametrize("phase", ["flush", "publish", "parent"])
def test_io_failure_no_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    output = tmp_path / "reports" / "out.md"

    def fail(*args: object) -> None:
        raise OSError("private-path-must-not-leak")

    if phase == "flush":
        monkeypatch.setattr(os, "fsync", fail)
    elif phase == "publish":
        monkeypatch.setattr(report_module, "_publish", fail)
    else:
        (tmp_path / "reports").write_bytes(b"not a directory")
    with pytest.raises(DomainError) as caught:
        write_report(output, "content")
    assert caught.value.code is DomainErrorCode.REPORT_WRITE_FAILED
    assert "private-path" not in str(caught.value)
    assert not output.exists()
    assert not list(tmp_path.rglob(".report-*.tmp"))


def test_racing_writer_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "out.md"
    publish = report_module._publish

    def race(staging: Path, destination: Path) -> None:
        destination.write_bytes(b"competitor")
        publish(staging, destination)

    monkeypatch.setattr(report_module, "_publish", race)
    with pytest.raises(DomainError) as caught:
        write_report(output, "ours")
    assert caught.value.code is DomainErrorCode.REPORT_OUTPUT_EXISTS
    assert output.read_bytes() == b"competitor"
    assert not list(tmp_path.glob(".report-*.tmp"))
