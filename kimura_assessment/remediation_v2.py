"""Deterministic remediation verification for the synthetic red-team assessment."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import json

from .red_team_v2 import (
    AttackCase, AttackRegistry, CaseResult, DEFAULT_REGISTRY, DEFAULT_TARGET,
    DeterministicAssessmentRunner, RedTeamAssessmentResult, SyntheticTargetProfile,
)


@dataclass(frozen=True, slots=True)
class RemediationPolicy:
    policy_id: str
    denied_actions: frozenset[str]

    def apply(self, target: SyntheticTargetProfile) -> SyntheticTargetProfile:
        return replace(target, allowlisted_actions=target.allowlisted_actions - self.denied_actions)


@dataclass(frozen=True, slots=True)
class ReplayEvidenceLink:
    attack_id: str
    original_evidence_id: str
    remediation_policy_id: str
    replay_evidence_id: str | None
    original_fixture_sha256: str
    replay_fixture_sha256: str | None
    identity_verified: bool
    final_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "attack_id": self.attack_id,
            "original_evidence_id": self.original_evidence_id,
            "remediation_policy_id": self.remediation_policy_id,
            "replay_evidence_id": self.replay_evidence_id,
            "original_fixture_sha256": self.original_fixture_sha256,
            "replay_fixture_sha256": self.replay_fixture_sha256,
            "identity_verified": self.identity_verified,
            "final_status": self.final_status,
        }


@dataclass(frozen=True, slots=True)
class RemediationVerificationResult:
    initial: RedTeamAssessmentResult
    replay: RedTeamAssessmentResult
    remediation_policy: RemediationPolicy
    initial_attack_paths_tested: int
    initial_validated_impacts: int
    successful_attack_ids: tuple[str, ...]
    replayed_attack_ids: tuple[str, ...]
    exact_replays_verified: int
    post_remediation_allowed: int
    post_remediation_blocked: int
    post_remediation_validated_impacts: int
    evidence_links: tuple[ReplayEvidenceLink, ...]
    remediation_verified: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "initial_attack_paths_tested": self.initial_attack_paths_tested,
            "initial_validated_impacts": self.initial_validated_impacts,
            "successful_attack_ids": list(self.successful_attack_ids),
            "replayed_attack_ids": list(self.replayed_attack_ids),
            "exact_replays_verified": self.exact_replays_verified,
            "post_remediation_allowed": self.post_remediation_allowed,
            "post_remediation_blocked": self.post_remediation_blocked,
            "post_remediation_validated_impacts": self.post_remediation_validated_impacts,
            "remediation_policy": self.remediation_policy.policy_id,
            "remediation_verified": self.remediation_verified,
            "evidence_links": [link.to_dict() for link in self.evidence_links],
        }


def _empty_result(target: SyntheticTargetProfile, registry_sha256: str) -> RedTeamAssessmentResult:
    return RedTeamAssessmentResult("kimura-agent-red-team-v2", target.target_id, registry_sha256, (), (), ())


def _same_replay_identity(original: CaseResult, replay: CaseResult) -> bool:
    return (
        original.attack_id == replay.attack_id
        and original.fixture_sha256 == replay.fixture_sha256
        and original.proposed_action == replay.proposed_action
    )


class RemediationVerifier:
    """Select runtime successes, apply policy, and execute exact replays."""

    def __init__(self, registry: AttackRegistry = DEFAULT_REGISTRY, target: SyntheticTargetProfile = DEFAULT_TARGET):
        self.registry = registry
        self.target = target

    def verify(
        self,
        *,
        remediation_policy: RemediationPolicy | None = None,
        replay_cases: tuple[AttackCase, ...] | None = None,
    ) -> RemediationVerificationResult:
        initial = DeterministicAssessmentRunner(self.registry, self.target).run()
        successful_ids = initial.successful_attack_ids
        cases_by_id = {case.attack_id: case for case in self.registry}
        selected_cases = tuple(cases_by_id[attack_id] for attack_id in successful_ids)
        policy = remediation_policy or RemediationPolicy(
            "deny-untrusted-validated-actions-v2",
            frozenset(case.proposed_action for case in selected_cases if case.proposed_action),
        )
        remediated_target = policy.apply(self.target)
        replay_input = selected_cases if replay_cases is None else replay_cases
        replayed_ids = tuple(case.attack_id for case in replay_input)
        if replay_input:
            replay_registry = AttackRegistry(tuple(sorted(replay_input, key=lambda case: case.attack_id)))
            replay = DeterministicAssessmentRunner(
                replay_registry, remediated_target,
                evidence_prefix="red-team-v2-replay-evidence", evidence_phase="retest", policy_id=policy.policy_id,
            ).run()
        else:
            replay = _empty_result(remediated_target, self.registry.registry_sha256)
        initial_by_id = {case.attack_id: case for case in initial.cases}
        replay_by_id = {case.attack_id: case for case in replay.cases}
        links = []
        for attack_id in successful_ids:
            original = initial_by_id[attack_id]
            retest = replay_by_id.get(attack_id)
            identity = retest is not None and _same_replay_identity(original, retest)
            passed = identity and not retest.ledger_validated_impact
            links.append(ReplayEvidenceLink(
                attack_id, original.evidence_id, policy.policy_id,
                retest.evidence_id if retest else None, original.fixture_sha256,
                retest.fixture_sha256 if retest else None, identity,
                "verified" if passed else "failed",
            ))
        exact_count = sum(link.identity_verified for link in links)
        verified = (
            set(replayed_ids) == set(successful_ids)
            and exact_count == len(successful_ids)
            and replay.validated_impacts == 0
        )
        return RemediationVerificationResult(
            initial, replay, policy, initial.attack_paths_tested, initial.validated_impacts,
            successful_ids, replayed_ids, exact_count, replay.allowed_actions,
            replay.blocked_actions, replay.validated_impacts, tuple(links), verified,
        )


def _summary(result: RemediationVerificationResult) -> str:
    lines = [
        "INITIAL ASSESSMENT",
        f"attack paths tested: {result.initial_attack_paths_tested}",
        f"validated impacts: {result.initial_validated_impacts}",
        "", "SUCCESSFUL ATTACKS", *result.successful_attack_ids, "",
        "REMEDIATION", f"policy: {result.remediation_policy.policy_id}", "", "EXACT REPLAY",
    ]
    for link in result.evidence_links:
        lines.extend([
            f"attack_id: {link.attack_id}",
            f"identity verified: {'yes' if link.identity_verified else 'no'}",
            f"before: {link.original_evidence_id}",
            f"remediation: {link.remediation_policy_id}",
            f"after: {link.replay_evidence_id or '(missing)'}",
            f"status: {link.final_status}",
        ])
    lines.extend([
        "", "VERIFICATION",
        f"before validated impacts: {result.initial_validated_impacts}",
        f"after validated impacts: {result.post_remediation_validated_impacts}",
        f"post-remediation allowed: {result.post_remediation_allowed}",
        f"post-remediation blocked: {result.post_remediation_blocked}",
        f"remediation verified: {str(result.remediation_verified).lower()}",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic remediation verification")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = RemediationVerifier().verify()
    print(json.dumps(result.to_dict(), sort_keys=True, indent=2) if args.json else _summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
