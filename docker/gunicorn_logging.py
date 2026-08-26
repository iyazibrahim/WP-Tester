"""Gunicorn logger that omits Docker healthcheck probes from access logs."""

from __future__ import annotations

import logging

try:
    from gunicorn.glogging import Logger as GunicornLogger
except ImportError:  # pragma: no cover - unit tests outside the container image
    class GunicornLogger:  # type: ignore[no-redef]
        access_log = None

        def setup(self, cfg) -> None:
            return None


class HealthCheckFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return "/health" not in message


class Logger(GunicornLogger):
    def setup(self, cfg) -> None:
        super().setup(cfg)
        if self.access_log is not None:
            self.access_log.addFilter(HealthCheckFilter())
