from importlib.metadata import version

import loader_detection_workbench


def test_package_imports() -> None:
    assert loader_detection_workbench.__doc__
    assert version("loader-detection-workbench") == "0.1.0"
