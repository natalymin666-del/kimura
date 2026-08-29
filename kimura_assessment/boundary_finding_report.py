"""Customer-readable reports derived from verified Boundary Proof evidence.

This layer is intentionally downstream of :mod:`boundary_proof`.  It does not
assign security truth; the existing independent verifier remains authoritative.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from html import escape
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .adaptive_boundary import AttackChain, AttackVariant
from .boundary_proof import (
    BoundaryProofCapsule, BoundaryTestPair, BoundaryVerdict,
    ContainedImpactEvidence, SafetyContract, independent_verdict, sha256,
)


class BoundaryFindingError(ValueError):
    """Raised when evidence cannot support a safe finding report."""


_SECRET_KEY = re.compile(r"(secret|password|token|api[_-]?key|credential|authorization)", re.I)
_SECRET_VALUE = re.compile(r"bearer\s+[^\s]+|sk-[A-Za-z0-9_-]+", re.I)


def redact(value: Any) -> Any:
    """Return a JSON-shaped, conservative redaction of customer-visible data."""
    if isinstance(value, Mapping):
        return {str(k): "[REDACTED]" if _SECRET_KEY.search(str(k)) else redact(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub("[REDACTED]", value)
    return value


def _text(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, ensure_ascii=False)


def _run_id(capsule: BoundaryProofCapsule) -> str | None:
    run_id = capsule.execution_evidence.get("run_id")
    return run_id if isinstance(run_id, str) and run_id else None


def _chain_status(chain: AttackChain | None) -> tuple[str, str]:
    if chain is None:
        return "NOT APPLICABLE", "No adaptive chain supplied."
    previous = None
    for transition in chain.transitions:
        if transition.provenance_link.get("proven") is not True:
            return "UNVERIFIED", "A chain transition lacks proven provenance."
        if previous is not None and dict(transition.precondition) != dict(previous.observable_postcondition):
            return "UNVERIFIED", "An intermediate chain precondition is not proven by the prior result."
        previous = transition
    return "VERIFIED", "Every recorded transition has linked observable provenance."


@dataclass(frozen=True, slots=True)
class BoundaryFinding:
    schema_version: int
    finding_id: str
    concise_title: str
    protected_boundary: str
    actor_authorization_context: Mapping[str, Any]
    allowed_twin_summary: Mapping[str, Any]
    forbidden_twin_summary: Mapping[str, Any]
    exact_boundary_difference: Mapping[str, Any]
    attack_variant_or_chain_lineage: Mapping[str, Any]
    authorization_result: str
    tool_action: Mapping[str, Any]
    state_before: Mapping[str, Any]
    state_after: Mapping[str, Any]
    observable_impact: Mapping[str, Any]
    independent_kimura_verdict: str
    proof_capsule_reference: str
    causal_provenance_status: str
    remediation_status: str
    exact_retest_status: str
    allowed_function_preservation_status: str
    limitations: tuple[str, ...]
    evidence_confidence_state: str
    run_identity: str
    contract_fingerprint: str
    pair_fingerprint: str
    attack_chain_fingerprint: str

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not self.finding_id or not self.proof_capsule_reference:
            raise BoundaryFindingError("finding identity is incomplete")
        if self.independent_kimura_verdict not in {v.value for v in BoundaryVerdict}:
            raise BoundaryFindingError("unsupported canonical Kimura verdict")
        if self.independent_kimura_verdict == BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED.value:
            if self.observable_impact.get("confirmed") is not True:
                raise BoundaryFindingError("confirmed finding requires observable impact")
            if self.causal_provenance_status != "VERIFIED":
                raise BoundaryFindingError("confirmed finding requires verified provenance")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["limitations"] = list(self.limitations)
        return redact(result)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_boundary_finding(*, finding_id: str, contract: SafetyContract,
                           pair: BoundaryTestPair, allowed: ContainedImpactEvidence,
                           forbidden: ContainedImpactEvidence, capsule: BoundaryProofCapsule,
                           run_id: str | None = None, variant: AttackVariant | None = None,
                           chain: AttackChain | None = None) -> BoundaryFinding:
    """Build a report solely from a pair, observations, and a verified capsule."""
    try:
        capsule.verify()
    except ValueError as exc:
        raise BoundaryFindingError("capsule mismatch; report fails closed") from exc
    actual_run = _run_id(capsule)
    if not actual_run or (run_id is not None and run_id != actual_run):
        raise BoundaryFindingError("run identity is missing or mismatched")
    if pair.safety_contract_fingerprint != contract.fingerprint or capsule.safety_contract_fingerprint != contract.fingerprint:
        raise BoundaryFindingError("contract binding mismatch")
    if capsule.boundary_test_pair_fingerprint != pair.fingerprint:
        raise BoundaryFindingError("pair binding mismatch")
    if (dict(allowed.attempted_action) != dict(pair.allowed_twin.canonical_request)
            or dict(forbidden.attempted_action) != dict(pair.forbidden_twin.canonical_request)
            or dict(capsule.canonical_request) != dict(pair.forbidden_twin.canonical_request)):
        raise BoundaryFindingError("cross-pair evidence rejected")
    evidence_runs = {item.tool_execution.get("run_id") for item in (allowed, forbidden)}
    if evidence_runs != {actual_run}:
        raise BoundaryFindingError("cross-run evidence rejected")
    if capsule.verdict_inputs.get("model_prose") is not None:
        raise BoundaryFindingError("model prose cannot create a finding")
    causal = capsule.causal_provenance or {}
    provenance = "VERIFIED" if causal.get("proven") is True else "MISSING / UNVERIFIED"
    chain_status, chain_note = _chain_status(chain)
    if chain is not None and chain_status != "VERIFIED":
        kimura_verdict = BoundaryVerdict.INCONCLUSIVE
    else:
        kimura_verdict = independent_verdict(forbidden=forbidden, allowed=allowed, capsule=capsule)
    if provenance != "VERIFIED" and kimura_verdict == BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED:
        kimura_verdict = BoundaryVerdict.INCONCLUSIVE
    impact = {"confirmed": forbidden.impact_confirmed, "effect_count": forbidden.effect_count,
              "state_delta": forbidden.state_delta, "effect_identity": forbidden.effect_identity}
    if kimura_verdict == BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED and not forbidden.impact_confirmed:
        kimura_verdict = BoundaryVerdict.INCONCLUSIVE
    remediation = capsule.remediation_evidence
    retest = capsule.exact_retest_evidence
    preservation = capsule.allowed_function_preservation_evidence
    chain_steps = ([{"precondition": t.precondition, "action": t.action, "observable_result": t.observable_postcondition, "provenance": t.provenance_link} for t in chain.transitions] if chain else [])
    return BoundaryFinding(
        1, finding_id, f"{contract.protected_boundary_identity.get('boundary', 'Protected boundary')} boundary result",
        _text(contract.protected_boundary_identity), redact(contract.actor_identity_constraints),
        {"twin_id": pair.allowed_twin.twin_id, "request": pair.allowed_twin.canonical_request, "expected": "ALLOWED"},
        {"twin_id": pair.forbidden_twin.twin_id, "request": pair.forbidden_twin.canonical_request, "expected": "FORBIDDEN"},
        pair.explicit_boundary_difference,
        {"variant": variant.to_unsigned() if variant else None, "chain_id": chain.chain_id if chain else None,
         "chain_steps": chain_steps, "chain_provenance": chain_status, "chain_note": chain_note},
        forbidden.authorization_decision, {"attempted_action": forbidden.attempted_action,
        "execution": forbidden.tool_execution}, forbidden.state_before, forbidden.state_after, impact,
        kimura_verdict.value, capsule.capsule_id, provenance,
        "VERIFIED" if remediation.get("verified") is True and retest.get("complete") is True else "NOT VERIFIED / NOT RUN",
        "VERIFIED" if retest.get("complete") is True else "NOT VERIFIED / NOT RUN",
        "VERIFIED" if preservation.get("verified") is True and allowed.impact_confirmed else "NOT VERIFIED / UNKNOWN",
        ("Synthetic/local fixture only.", "This report describes the recorded boundary, not the whole system.",),
        "HIGH" if kimura_verdict in {BoundaryVerdict.BOUNDARY_VIOLATION_CONFIRMED, BoundaryVerdict.BOUNDARY_HELD} and provenance == "VERIFIED" else "LIMITED",
        actual_run, contract.fingerprint, pair.fingerprint, chain.fingerprint if chain else "NOT APPLICABLE")


def render_boundary_finding_html(finding: BoundaryFinding) -> str:
    """Render a self-contained offline customer report."""
    d = finding.to_dict()
    verdict = escape(finding.independent_kimura_verdict)
    chain = d["attack_variant_or_chain_lineage"]
    steps = ""
    if chain.get("chain_id"):
        steps = "<h3>Chain reporting</h3>" + "".join(
            f"<p><b>STEP {i}</b> {_text(t['precondition'])} → {_text(t['action'])} → {_text(t['observable_result'])}</p>"
            for i, t in enumerate(chain.get("chain_steps", []), 1))
        steps += f"<p><b>FINAL PROTECTED BOUNDARY</b> {escape(finding.protected_boundary)}</p><p><b>FINAL OBSERVABLE IMPACT</b> {_text(finding.observable_impact)}</p><p><b>CHAIN PROVENANCE VERIFIED</b> {escape(str(chain['chain_provenance']))}</p>"
    proof = {"contract_fingerprint": finding.contract_fingerprint, "pair_fingerprint": finding.pair_fingerprint,
             "attack_chain_fingerprint": finding.attack_chain_fingerprint, "capsule_sha256": finding.proof_capsule_reference,
             "run_identity": finding.run_identity, "provenance_verification": finding.causal_provenance_status,
             "state_effect_evidence_references": {"state_before": finding.state_before, "state_after": finding.state_after,
             "observable_impact": finding.observable_impact}}
    summary = (f"The tested boundary was {finding.protected_boundary}. The allowed twin was recorded as allowed; "
               f"the forbidden twin was recorded as forbidden. The forbidden action {'occurred' if finding.observable_impact.get('confirmed') else 'did not have confirmed impact'}. "
               f"Kimura verdict: {verdict}.")
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kimura Boundary Finding</title><style>body{{font:15px/1.5 system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#17202a}}section{{border:1px solid #d7dde5;border-radius:10px;padding:1rem;margin:1rem 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fa;padding:1rem;border-radius:8px}}.verdict{{font-weight:800;color:#075985}}</style></head><body><header><h1>Kimura Boundary Finding</h1><p class="verdict">{verdict}</p></header><section><h2>Customer summary</h2><p>{escape(summary)}</p><p>Observable impact: <code>{escape(_text(finding.observable_impact))}</code></p><p>Run identity and capsule hash bind this report to the exact recorded assessment. Remediation: {escape(finding.remediation_status)}. Legitimate functionality: {escape(finding.allowed_function_preservation_status)}.</p><p>Unknown: {escape('; '.join(finding.limitations))}</p></section><section><h2>Finding</h2><pre>{escape(json.dumps(d, indent=2, sort_keys=True))}</pre>{steps}</section><section><h2>Proof section</h2><pre>{escape(json.dumps(redact(proof), indent=2, sort_keys=True))}</pre></section><section><h2>Outcome interpretation</h2><p>CONFIRMED means observable forbidden impact was verified. BOUNDARY HELD means the forbidden action was blocked with no effect. INCONCLUSIVE means the evidence is insufficient and is not a pass. HARNESS / INFRA FAILURE is a separate assessment-operability result and is never converted into a security verdict.</p></section><footer><p><b>Claim boundary:</b> Kimura validates the tested action boundary under the recorded assessment conditions. It does not establish that the entire agent or system is secure.</p></footer></body></html>'''


def write_boundary_finding_html(finding: BoundaryFinding, path: Path) -> None:
    path.write_text(render_boundary_finding_html(finding), encoding="utf-8", newline="\n")


def build_local_demo_finding() -> BoundaryFinding:
    """Build one offline demo from the existing synthetic privilege fixture."""
    from dataclasses import replace
    from .privilege_boundary import build_privilege_baseline, build_privilege_proof_capsule

    contract, pair, _env, allowed, forbidden = build_privilege_baseline()
    run_id = "phase-10.1-local-demo-run"
    allowed = replace(allowed, tool_execution={**allowed.tool_execution, "run_id": run_id})
    forbidden = replace(forbidden, tool_execution={**forbidden.tool_execution, "run_id": run_id})
    capsule = build_privilege_proof_capsule(contract, pair, allowed, forbidden)
    capsule = replace(capsule,
        authorization_evidence={"allowed": "ALLOWED", "forbidden": "ALLOWED", "run_id": run_id},
        execution_evidence={"allowed": allowed.tool_execution, "forbidden": forbidden.tool_execution, "run_id": run_id},
        causal_provenance={"proven": True, "source": "local-observable-state-and-effect"})
    capsule = replace(capsule, capsule_sha256=sha256(capsule.to_unsigned()))
    return build_boundary_finding(finding_id="BF-10.1-001", contract=contract, pair=pair,
        allowed=allowed, forbidden=forbidden, capsule=capsule, run_id=run_id)
