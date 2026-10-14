from importlib.metadata import version
from importlib.resources import files

import loader_detection_workbench


def test_package_imports() -> None:
    assert loader_detection_workbench.__doc__
    assert version("loader-detection-workbench") == "0.1.0"


def test_web_resources_are_packaged() -> None:
    package = files("loader_detection_workbench.web")
    assert package.joinpath("templates", "base.html").is_file()
    assert package.joinpath("static", "workbench.css").is_file()
