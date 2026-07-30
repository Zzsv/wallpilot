"""Compatibility helpers for supported Python versions."""

from datetime import timezone
from enum import Enum

UTC = timezone.utc


class StrEnum(str, Enum):
    """String enum with the behavior WallPilot needs on Python 3.10+."""

    def __str__(self) -> str:
        return str(self.value)
