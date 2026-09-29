"""Errors a service sees or raises (gateway spec sections 6.1 and 6.3)."""

from __future__ import annotations

# Section 6.3: the codes a service may put on an `error` message.
NOT_ALLOWED = "not_allowed"
NOT_FOUND = "not_found"
BAD_ARGUMENTS = "bad_arguments"
UNAVAILABLE = "unavailable"
TIMED_OUT = "timed_out"
RATE_LIMITED = "rate_limited"
INTERNAL = "internal"
ERROR_CODES = frozenset({
    NOT_ALLOWED, NOT_FOUND, BAD_ARGUMENTS, UNAVAILABLE, TIMED_OUT, RATE_LIMITED, INTERNAL,
})


class ServiceError(Exception):
    """Raise from `on_call` / `on_read` to answer with a section 6.3 error.

    `code` is readable by the gateway; `message` is the payload (sealed to the
    client in `end-to-end` mode). Anything else a handler raises becomes
    `internal` with a generic message.
    """

    def __init__(self, code: str, message: str) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"{code!r} is not a section 6.3 error code "
                             f"({', '.join(sorted(ERROR_CODES))})")
        super().__init__(message)
        self.code = code
        self.message = message


class ConfigError(ValueError):
    """The service's configuration is missing or invalid. Raised at start."""


class RegistrationRejected(RuntimeError):
    """The gateway answered `rejected {reason}` to a re-registration sent by
    `GatewayService.update()`. `reason` is a section 6.1 reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"registration rejected: {reason}")
        self.reason = reason
