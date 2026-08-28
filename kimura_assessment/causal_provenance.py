"""Structured causal links for future Boundary Proof evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .boundary_proof import canonical_json, sha256


@dataclass(frozen=True, slots=True)
class CausalProvenance:
    request_identity: Mapping[str, Any]
    authorization_identity: Mapping[str, Any]
    execution_identity: Mapping[str, Any]
    effect_identity: Mapping[str, Any]
    state_transition_identity: Mapping[str, Any]
    proven: bool

    def __post_init__(self) -> None:
        if not isinstance(self.proven, bool):
            raise ValueError("causal provenance proven flag is invalid")
        for name in ("request_identity", "authorization_identity", "execution_identity",
                     "effect_identity", "state_transition_identity"):
            value = getattr(self, name)
            if not isinstance(value, Mapping) or not value:
                raise ValueError(f"causal provenance {name} is missing")
            canonical_json(dict(value))

    def to_dict(self) -> dict[str, Any]:
        return {"request_identity": dict(self.request_identity),
                "authorization_identity": dict(self.authorization_identity),
                "execution_identity": dict(self.execution_identity),
                "effect_identity": dict(self.effect_identity),
                "state_transition_identity": dict(self.state_transition_identity),
                "proven": self.proven}

    @property
    def fingerprint(self) -> str:
        return sha256(self.to_dict())


def prove_causal_provenance(*, request: Mapping[str, Any], authorization: Mapping[str, Any],
                            execution: Mapping[str, Any], effect: Mapping[str, Any],
                            state_transition: Mapping[str, Any], run_identity: Mapping[str, Any],
                            fixture_identity: str, twin_identity: str) -> CausalProvenance:
    """Create provenance only when every link carries the same run/fixture/twin."""
    common = {"run_identity": dict(run_identity), "fixture_identity": fixture_identity,
              "twin_identity": twin_identity}
    request_id = {**common, "request_fingerprint": sha256(request)}
    authorization_id = {**common, "request_fingerprint": request_id["request_fingerprint"],
                        "decision": authorization.get("decision")}
    execution_id = {**common, "request_fingerprint": request_id["request_fingerprint"],
                    "authorization_fingerprint": sha256(authorization),
                    "tool_call_id": execution.get("tool_call_id"),
                    "executed": execution.get("executed")}
    effect_id = {**common, "execution_fingerprint": sha256(execution),
                 "effect_fingerprint": sha256(effect), "effect_count": effect.get("effect_count")}
    state_id = {**common, "effect_fingerprint": effect_id["effect_fingerprint"],
                "state_before_fingerprint": sha256(state_transition.get("state_before", {})),
                "state_after_fingerprint": sha256(state_transition.get("state_after", {}))}
    return CausalProvenance(request_id, authorization_id, execution_id, effect_id, state_id, True)


def validate_causal_provenance(provenance: CausalProvenance | Mapping[str, Any], *,
                               request: Mapping[str, Any], authorization: Mapping[str, Any],
                               execution: Mapping[str, Any], effect: Mapping[str, Any],
                               state_transition: Mapping[str, Any], run_identity: Mapping[str, Any],
                               fixture_identity: str, twin_identity: str) -> bool:
    try:
        value = provenance if isinstance(provenance, CausalProvenance) else CausalProvenance(**dict(provenance))
        expected = prove_causal_provenance(request=request, authorization=authorization,
            execution=execution, effect=effect, state_transition=state_transition,
            run_identity=run_identity, fixture_identity=fixture_identity, twin_identity=twin_identity)
        return value.proven and value.to_dict() == expected.to_dict()
    except (TypeError, ValueError):
        return False
