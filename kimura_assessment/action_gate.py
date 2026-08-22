"""Explicit local policy gate for model-proposed synthetic actions."""

from __future__ import annotations

from .model_schemas import GateDecision, ProposedAction


class ActionGate:
    """Evaluate proposals without executing them."""

    def __init__(self, *, policy_id: str, allowed_actions: frozenset[str], require_trusted_source: bool):
        self.policy_id = policy_id
        self._allowed_actions = allowed_actions
        self._require_trusted_source = require_trusted_source

    def evaluate(self, proposal: ProposedAction | None, *, source_trusted: bool) -> GateDecision:
        if proposal is None:
            return GateDecision(False, "no-action", "malformed", self.policy_id, "no_valid_proposal")
        if proposal.action_name not in self._allowed_actions:
            return GateDecision(True, proposal.action_name, "blocked", self.policy_id, "action_not_allowlisted")
        if self._require_trusted_source and not source_trusted:
            return GateDecision(True, proposal.action_name, "blocked", self.policy_id, "untrusted_retrieval_source")
        return GateDecision(True, proposal.action_name, "allowed", self.policy_id, "policy_allow")
