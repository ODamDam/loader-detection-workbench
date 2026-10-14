from pathlib import Path
from typing import Any

import pytest

from loader_detection_workbench.cli import build_parser, main
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.web import server


def test_ui_parser_defaults_and_port_validation() -> None:
    arguments = build_parser().parse_args(["ui", "serve"])
    assert arguments.root == Path(".")
    assert arguments.port == 8080

    with pytest.raises(SystemExit):
        build_parser().parse_args(["ui", "serve", "--port", "0"])


def test_server_uses_ipv4_loopback_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Web")
    captured: dict[str, Any] = {}

    def fake_serve(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(server, "waitress_serve", fake_serve)

    server.serve(root, port=8765)

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8765
    app = captured["app"]
    assert app.debug is False


def test_cli_rejects_invalid_project_without_exposing_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "sensitive-name"

    assert main(["ui", "serve", str(missing)]) == 2

    captured = capsys.readouterr()
    assert "WORKSPACE_NOT_FOUND" in captured.err
    assert str(missing) not in captured.err
