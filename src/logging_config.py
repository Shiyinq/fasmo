import contextvars
import logging
import os
import sys
from logging import Formatter
from logging.handlers import TimedRotatingFileHandler

from uvicorn.logging import ColourizedFormatter

from src.config import config

request_id_ctx_var = contextvars.ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    """
    Filter that injects the request_id from contextvars into the log record.
    """

    def filter(self, record):
        record.request_id = request_id_ctx_var.get("-")
        # For console logs using ColourizedFormatter, 'bind' is used as the logger name placeholder
        # For file logs using standard Formatter, this attribute is ignored/unused
        record.bind = record.name
        return True


def create_logger(app_name, name):
    logger = logging.getLogger(name)

    # Check if logger already has handlers to prevent duplication
    if logger.handlers:
        return logger

    LOGGING_LEVEL = getattr(logging, config.log_level.upper(), logging.INFO)
    # Standard Format for file logs (matched to console format preference)
    LOGGING_FORMAT = (
        "%(levelname)s [%(asctime)s] [%(name)s] [%(request_id)s] %(message)s"
    )

    handler = None
    
    if config.log_destination.lower() == "file":
        # FILE HANDLER CONFIGURATION
        LOG_PATH = "logs/" if config.is_env_dev else config.log_path
        if not os.path.exists(LOG_PATH):
            os.makedirs(LOG_PATH, exist_ok=True)

        LOGGING_FILENAME = f"{LOG_PATH}/{app_name}.log"
        handler = TimedRotatingFileHandler(
            LOGGING_FILENAME, when="D", interval=1, backupCount=7
        )
        handler.suffix = "%Y-%m-%d"
        # Use standard formatter for files
        handler.setFormatter(Formatter(LOGGING_FORMAT))
        
    else:
        # CONSOLE/STREAM HANDLER CONFIGURATION (Default)
        handler = logging.StreamHandler(sys.stdout)
        
        if config.is_env_dev:
            # Use Uvicorn's color formatter for local development
            formatter = ColourizedFormatter(
                "{levelprefix} [{asctime}] [{bind}] [{request_id}] {message}",
                style="{",
                use_colors=True
            )
        else:
            # Standard formatter for production console logs
            formatter = Formatter(LOGGING_FORMAT)

        handler.setFormatter(formatter)

    # Configure Handler Level
    handler.setLevel(LOGGING_LEVEL)

    # Configure Logger
    logger.setLevel(LOGGING_LEVEL)
    logger.addHandler(handler)
    
    # Attach filter (runs before handler to inject request_id)
    logger.addFilter(RequestIdFilter())
    
    logger.propagate = False  # Prevent propagation to root logger

    return logger
