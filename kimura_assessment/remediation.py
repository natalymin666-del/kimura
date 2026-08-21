"""Explicit remediation control for the local agent demo."""

from __future__ import annotations


class RemediationController:
    """Switch the local policy from vulnerable to deny-by-default."""

    def __init__(self, app):
        self._app = app

    def apply(self) -> str:
        self._app.enable_tool_policy()
        return "tool-policy-deny-untrusted-external-actions"
