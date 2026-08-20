from pathlib import Path
from unittest.mock import patch

import pytest

from loader_detection_workbench.config import (
    ConfigFileNotFoundError,
    ConfigReadError,
    ConfigSyntaxError,
    ConfigValueError,
    WorkbenchConfig,
    load_config,
)


def test_missing_config_uses_safe_defaults() -> None:
    assert load_config(None) == WorkbenchConfig(log_level="INFO")


def test_valid_config_loads_from_windows_style_path(tmp_path: Path) -> None:
    config_path = tmp_path / "OneDrive style 폴더" / "workbench.toml"
    config_path.parent.mkdir()
    config_path.write_text('[workbench]\nlog_level = "debug"\n', encoding="utf-8")

    assert load_config(config_path).log_level == "DEBUG"


def test_unknown_sections_and_keys_do_not_freeze_the_config_contract(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "future.toml"
    config_path.write_text(
        '[workbench]\nlog_level = "INFO"\nfuture_key = true\n'
        "[future]\nenabled = true\n",
        encoding="utf-8",
    )

    assert load_config(config_path).log_level == "INFO"


def test_explicit_missing_path_has_safe_error(tmp_path: Path) -> None:
    missing_path = tmp_path / "private" / "missing.toml"

    with pytest.raises(ConfigFileNotFoundError) as caught:
        load_config(missing_path)

    assert str(missing_path) not in str(caught.value)


def test_read_failure_has_safe_error(tmp_path: Path) -> None:
    config_path = tmp_path / "secret-config.toml"

    with (
        patch.object(Path, "open", side_effect=PermissionError("sensitive path")),
        pytest.raises(ConfigReadError) as caught,
    ):
        load_config(config_path)

    assert "sensitive path" not in str(caught.value)
    assert str(config_path) not in str(caught.value)


def test_invalid_toml_does_not_expose_contents_or_path(tmp_path: Path) -> None:
    secret = "SENTINEL_SECRET_VALUE"
    config_path = tmp_path / "private config.toml"
    config_path.write_text(f'[workbench]\nlog_level = "{secret}\n', encoding="utf-8")

    with pytest.raises(ConfigSyntaxError) as caught:
        load_config(config_path)

    message = str(caught.value)
    assert secret not in message
    assert str(config_path) not in message


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("workbench = true\n", "must be a TOML table"),
        ("[workbench]\nlog_level = 10\n", "must be a string"),
        ('[workbench]\nlog_level = "TRACE"\n', "unsupported log level"),
    ],
)
def test_invalid_supported_values_are_distinguished(
    tmp_path: Path,
    contents: str,
    message: str,
) -> None:
    config_path = tmp_path / "invalid.toml"
    config_path.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigValueError, match=message):
        load_config(config_path)
