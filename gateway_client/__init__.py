"""Shared client library for services of the Wolf MCP Gateway (service
contract version 2: GW-3 caller tokens verified on every call). See
README.md."""

from .caller_token import CallerTokenVerifier, KeySet, TokenRefused, VerifiedToken
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
from .protocol import CONTRACT_VERSION
from .service import Caller, GatewayService

__version__ = "0.2.0"

__all__ = [
    "BAD_ARGUMENTS", "CONTRACT_VERSION", "ERROR_CODES", "INTERNAL", "NOT_ALLOWED",
    "NOT_FOUND", "RATE_LIMITED", "TIMED_OUT", "UNAVAILABLE",
    "Caller", "CallerTokenVerifier", "Config", "ConfigError", "GatewayService",
    "KeyPair", "KeySet", "RegistrationRejected", "ServiceError", "TokenRefused",
    "VerifiedToken", "__version__",
]
