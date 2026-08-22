"""Provider-neutral boundary for model inference."""

from __future__ import annotations

from typing import Protocol

from .model_schemas import ModelRequest, ModelResponse


class ModelProviderError(RuntimeError):
    """A safe provider failure with no raw provider data."""


class ModelProvider(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse:
        """Return parsed, safe metadata; never execute tools."""
