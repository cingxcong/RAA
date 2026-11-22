"""Typed errors shared by every RAA surface."""

from __future__ import annotations

from typing import Any


class RAAError(Exception):
    """Base error with a stable machine-readable code."""

    code: str = "internal_error"
    http_status: int = 500
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.hint:
            payload["hint"] = self.hint
        if self.details:
            payload["details"] = self.details
        return payload


class InvalidArgumentsError(RAAError):
    code = "invalid_arguments"
    http_status = 400


class PolicyDeniedError(RAAError):
    code = "policy_denied"
    http_status = 403


class ProfileDeniedError(RAAError):
    code = "profile_denied"
    http_status = 403


class NotFoundError(RAAError):
    code = "not_found"
    http_status = 404


class ConflictError(RAAError):
    code = "conflict"
    http_status = 409


class StateError(RAAError):
    code = "invalid_state"
    http_status = 409


class InvalidArtifactError(RAAError):
    code = "invalid_artifact"
    http_status = 422


class LimitExceededError(RAAError):
    code = "limit_exceeded"
    http_status = 413


class UnsupportedError(RAAError):
    code = "unsupported"
    http_status = 501


class EngineUnavailableError(RAAError):
    code = "engine_unavailable"
    http_status = 503
    retryable = True


class EngineExecutionError(RAAError):
    code = "engine_failed"
    http_status = 502
    retryable = True


class EngineTimeoutError(RAAError):
    code = "engine_timeout"
    http_status = 504
    retryable = True


class InternalError(RAAError):
    code = "internal_error"
    http_status = 500
