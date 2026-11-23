"""Waitress entry boundary for the loopback-only UI."""

from pathlib import Path

from waitress import serve as waitress_serve  # type: ignore[import-untyped]

from loader_detection_workbench.web.app import create_app


def serve(project_root: Path, *, port: int) -> None:
    app = create_app(project_root, port=port)
    print(f"ui: http://127.0.0.1:{port}")
    waitress_serve(app, host="127.0.0.1", port=port)
