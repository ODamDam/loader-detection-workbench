import logging
from pathlib import Path

import pytest

from loader_detection_workbench.cli import main
from loader_detection_workbench.logging_config import LOGGER_NAME


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])

    assert caught.value.code == 0
    output = capsys.readouterr().out
    assert "--config" in output
    assert "--log-level" in output


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])

    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == "workbench 0.1.0"


def test_cli_uses_default_config() -> None:
    assert main([]) == 0
    assert logging.getLogger(LOGGER_NAME).level == logging.INFO


def test_cli_configures_valid_file(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('[workbench]\nlog_level = "WARNING"\n', encoding="utf-8")

    assert main(["--config", str(config_path)]) == 0
    assert logging.getLogger(LOGGER_NAME).level == logging.WARNING


def test_cli_log_level_overrides_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('[workbench]\nlog_level = "WARNING"\n', encoding="utf-8")

    assert main(["--config", str(config_path), "--log-level", "debug"]) == 0
    assert logging.getLogger(LOGGER_NAME).level == logging.DEBUG


def test_invalid_log_level_is_a_clear_cli_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--log-level", "TRACE"])

    assert caught.value.code == 2
    assert "unsupported log level" in capsys.readouterr().err


def test_config_error_does_not_expose_absolute_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_path = tmp_path / "private folder" / "missing.toml"

    with pytest.raises(SystemExit) as caught:
        main(["--config", str(missing_path)])

    assert caught.value.code == 2
    error = capsys.readouterr().err
    assert "configuration file was not found" in error
    assert str(missing_path) not in error
