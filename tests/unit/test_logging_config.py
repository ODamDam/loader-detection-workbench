import logging

from loader_detection_workbench.logging_config import (
    LOGGER_NAME,
    configure_console_logging,
)


def test_default_info_console_logging(capsys: object) -> None:
    logger = configure_console_logging("INFO")
    logger.debug("hidden")
    logger.info("ready")

    assert logger.level == logging.INFO
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.StreamHandler)
    assert logger.propagate is False


def test_requested_log_level_is_applied() -> None:
    logger = configure_console_logging("ERROR")

    assert logger.name == LOGGER_NAME
    assert logger.level == logging.ERROR
