import logging


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Sets up a logger with the specified name and logging level.

    Args:
        name (str): The name of the logger.
        level (int): The logging level (default: logging.INFO).

    Returns:
        logging.Logger: The configured logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


my_logger = setup_logger("my_logger")
if __name__ == "__main__":
    my_logger.debug("This is a debug message")
    my_logger.info("This is an info message")
    my_logger.warning("This is a warning message")
    my_logger.error("This is an error message")
    my_logger.critical("This is a critical message")
