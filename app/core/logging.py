import logging

import structlog


def configure_logging() -> None:
    """
    Configure structlog as the single logging backend.
    Called once at application startup in main.py lifespan.
    Produces JSON logs with consistent fields on every line:
    timestamp, level, and all keyword arguments passed at
    the call site.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
