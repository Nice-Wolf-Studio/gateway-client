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
from .service import Caller, GatewayService

__version__ = "0.1.0"

__all__ = [
    "BAD_ARGUMENTS", "ERROR_CODES", "INTERNAL", "NOT_ALLOWED", "NOT_FOUND",
    "RATE_LIMITED", "TIMED_OUT", "UNAVAILABLE",
    "Caller", "Config", "ConfigError", "GatewayService", "KeyPair",
    "RegistrationRejected", "ServiceError", "__version__",
]
