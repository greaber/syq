"""Shared client-default sentinel; None explicitly disables a timeout."""

from enum import Enum


class _ClientDefault(Enum):
    TIMEOUT = "client timeout"

    def __repr__(self) -> str:
        return "CLIENT_DEFAULT"


CLIENT_DEFAULT = _ClientDefault.TIMEOUT
Timeout = float | None | _ClientDefault


def resolve_timeout(value: Timeout, default: float | None) -> float | None:
    if isinstance(value, _ClientDefault):
        return default
    return value
