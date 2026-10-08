"""Shared client library for services of the Wolf MCP Gateway (service
contract version 1, with legacy-protocol fallback). See README.md."""

from .config import Config
from .e2e import KeyPair
from .errors import (
    BAD_ARGUMENTS,
    ERROR_CODES,
    INTERNAL,
    NOT_ALLOWED,
    NOT_FOUND,
    RATE_LIMITED,
    TIMED_OUT,
    UNAVAILABLE,
    ConfigError,
    RegistrationRejected,
    ServiceError,
)
from .logs import (
    JsonFormatter,
    RequestIdFilter,
    configure_logging,
    current_request_id,
)
from .service import Caller, GatewayService

__version__ = "0.2.0"

__all__ = [
    "BAD_ARGUMENTS", "ERROR_CODES", "INTERNAL", "NOT_ALLOWED", "NOT_FOUND",
    "RATE_LIMITED", "TIMED_OUT", "UNAVAILABLE",
    "Caller", "Config", "ConfigError", "GatewayService", "JsonFormatter", "KeyPair",
    "RegistrationRejected", "RequestIdFilter", "ServiceError", "__version__",
    "configure_logging", "current_request_id",
]
