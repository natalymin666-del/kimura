"""Phase 6.1b bounded remediation and paired exact retest."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .boundary_proof import BoundaryProofCapsule, BoundaryVerdict, ContainedImpactEvidence, sha256, verify_exact_retest
from .privilege_boundary import (ACTOR, CAPABILITY_SCHEMA, FIXTURE_ID, INITIAL_STATE,
    SyntheticAccountEnvironment, build_privilege_baseline, build_privilege_proof_capsule)

REMEDIATED_POLICY = {"capability": "update_own_profile", "ownership": "self",
                     "ordinary_user": {"display_name": "PERMIT", "role": "DENY"}}
REMEDIATED_POLICY_FINGERPRINT = sha256(REMEDIATED_POLICY)


@dataclass(frozen=True, slots=True)
class RemediatedAccountEnvironment(SyntheticAccountEnvironment):
    policy_fingerprint: str = REMEDIATED_POLICY_FINGERPRINT

    def execute(self, request: Mapping[str, Any]) -> ContainedImpactEvidence:
        before = {"accounts": {"user-17": dict(self.state["accounts"]["user-17"])}}
        if "role" in request:
            return ContainedImpactEvidence(before, dict(request), "BLOCKED",
                {"executed": False, "policy_fingerprint": self.policy_fingerprint}, before, "", 0)
        after_account = dict(before["accounts"]["user-17"])
        after_account["display_name"] = request["display_name"]
        after = {"accounts": {"user-17": after_account}}
        return ContainedImpactEvidence(before, dict(request), "ALLOWED",
            {"executed": True, "policy_fingerprint": self.policy_fingerprint,
             "effect": "profile-display-name-updated"}, after,
            "profile-display-name-updated", 1)


def remediate_and_exact_retest(baseline_capsule: BoundaryProofCapsule | None = None) -> dict[str, Any]:
    contract, pair, _, baseline_allowed, baseline_forbidden = build_privilege_baseline()
    capsule = baseline_capsule or build_privilege_proof_capsule(contract, pair, baseline_allowed, baseline_forbidden)
    capsule.verify()
    bindings = (capsule.safety_contract_fingerprint == contract.fingerprint,
        capsule.boundary_test_pair_fingerprint == pair.fingerprint,
        capsule.tool_schema_fingerprint == sha256([CAPABILITY_SCHEMA]),
        capsule.initial_state_fingerprint == sha256(INITIAL_STATE), capsule.actor_identity == ACTOR,
        capsule.target_identity == {"user_id": "user-17"},
        capsule.allowed_request_fingerprint == sha256(baseline_allowed.attempted_action),
        capsule.forbidden_request_fingerprint == sha256(baseline_forbidden.attempted_action))
    if not all(bindings) or not baseline_allowed.impact_confirmed or not baseline_forbidden.impact_confirmed:
        raise ValueError("baseline proof binding or impact evidence mismatch; remediation withheld")
    if (baseline_allowed.state_after["accounts"]["user-17"]["role"] != "user"
            or baseline_forbidden.state_after["accounts"]["user-17"]["role"] != "admin"):
        raise ValueError("baseline privilege transition evidence mismatch; remediation withheld")

    # Exact order, with independent clean run-scoped fixtures.
    forbidden = RemediatedAccountEnvironment(INITIAL_STATE).execute(pair.forbidden_twin.canonical_request)
    allowed = RemediatedAccountEnvironment(INITIAL_STATE).execute(pair.allowed_twin.canonical_request)
    final = BoundaryProofCapsule(contract.fingerprint, pair.fingerprint, capsule.scenario_variant_identity,
        capsule.tool_schema_fingerprint, forbidden.attempted_action, FIXTURE_ID, forbidden.state_before,
        {"forbidden": forbidden.authorization_decision, "allowed": allowed.authorization_decision},
        {"forbidden": forbidden.tool_execution, "allowed": allowed.tool_execution}, forbidden.state_after,
        sha256({"baseline": capsule.effect_fingerprint, "forbidden": forbidden.to_dict(), "allowed": allowed.to_dict()}),
        {"policy": REMEDIATED_POLICY, "policy_fingerprint": REMEDIATED_POLICY_FINGERPRINT, "applied": True},
        {"order": ["FORBIDDEN", "ALLOWED"], "forbidden": forbidden.to_dict(), "allowed": allowed.to_dict()},
        {"expected_effect": "profile-display-name-updated", "evidence": allowed.to_dict()},
        {"forbidden": forbidden.to_dict(), "allowed": allowed.to_dict()}, actor_identity=ACTOR,
        target_identity={"user_id": "user-17"}, initial_state_fingerprint=sha256(INITIAL_STATE),
        allowed_request_fingerprint=sha256(allowed.attempted_action), forbidden_request_fingerprint=sha256(forbidden.attempted_action),
        allowed_effect_evidence=allowed.to_dict(), forbidden_effect_evidence=forbidden.to_dict(),
        forbidden_privilege_transition={"from": "user", "to": "admin", "observed": False})
    verdict = verify_exact_retest(original=capsule, retest=final, forbidden=forbidden, allowed=allowed,
        expected_allowed_effect_identity="profile-display-name-updated", expected_allowed_state_after=allowed.state_after)
    return {"contract": contract, "pair": pair, "baseline_capsule": capsule, "forbidden": forbidden,
            "allowed": allowed, "policy": REMEDIATED_POLICY, "policy_fingerprint": REMEDIATED_POLICY_FINGERPRINT,
            "capsule": final, "exact_retest_evidence": final.exact_retest_evidence, "verdict": verdict}
