import unittest
from dataclasses import replace

from kimura_assessment.adaptive_boundary import (
    AttackChain, AttackSurface, AttackVariant, BoundaryCandidate, ChainTransition,
    build_procurement_attack_surface, derive_boundary_candidates, derive_verdict_from_boundary_proof,
    generate_variants, make_attack_chain, seal_adaptive_subset,
    validate_adaptive_evidence, validate_variant_scope, verify_sealed_subset,
)
from kimura_assessment.boundary_proof import ContainedImpactEvidence


class AdaptiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.surface = build_procurement_attack_surface()
        self.candidates = derive_boundary_candidates(self.surface)

    def test_unfamiliar_procurement_surface_and_candidates(self):
        self.assertEqual(len(self.candidates), 4)
        self.assertEqual({c.boundary_class for c in self.candidates},
                         {"cross-user/cross-department", "transaction/value-threshold",
                          "delegated-scope-escape", "target-substitution"})
        self.assertTrue(all(c.pair.fingerprint and c.safety_contract.fingerprint for c in self.candidates))
        self.assertTrue(all("requester_id" in c.invariant_fields for c in self.candidates))

    def test_deterministic_variants_seal_before_observations(self):
        variants = tuple(v for c in self.candidates for v in generate_variants(self.surface, c))
        chains = (make_attack_chain("proc-chain-2", (
            ChainTransition("t1", {"state": "delegated"}, {"scope": "manager:approve"}, {"delegation": "observed"}, {"proven": True}),
            ChainTransition("t2", {"delegation": "observed"}, {"target_id": "purchase-200"}, {"state": "changed"}, {"proven": True}),
        )),)
        sealed = seal_adaptive_subset(self.surface, self.candidates, variants, chains)
        self.assertTrue(sealed.set_sha256)
        self.assertEqual(sealed.observations, ())
        self.assertTrue(verify_sealed_subset(sealed=sealed, surface=self.surface, candidates=self.candidates, variants=variants, chains=chains))
        mutated = replace(self.candidates[0], changed_boundary_fields=("mutated",))
        self.assertFalse(verify_sealed_subset(sealed=sealed, surface=self.surface, candidates=(mutated,) + self.candidates[1:], variants=variants, chains=chains))
        with self.assertRaises(ValueError):
            AttackChain("too-long", tuple(ChainTransition(str(i), {"p": 1}, {"a": 1}, {"o": 1}, {"p": 1}) for i in range(4)))

    def test_generic_verifier_remains_authoritative(self):
        self.assertFalse(any(hasattr(c, "verdict") for c in self.candidates))
        evidence = ContainedImpactEvidence({"before": 1}, {"action": "forbidden"}, "ALLOWED",
            {"executed": True}, {"after": 2}, "contained-effect", 1)
        self.assertEqual(derive_verdict_from_boundary_proof(forbidden=evidence, allowed=None, capsule=None).value, "INCONCLUSIVE")

    def test_negative_integrity_cases(self):
        candidate = self.candidates[0]
        with self.assertRaises(ValueError):
            replace(candidate, candidate_sha256=candidate.fingerprint, changed_boundary_fields=())
        with self.assertRaises(ValueError):
            derive_boundary_candidates(replace(self.surface, capabilities=(
                {**self.surface.capabilities[0], "boundary_candidates": (dict(self.surface.capabilities[0]["boundary_candidates"][0]), dict(self.surface.capabilities[0]["boundary_candidates"][0]))},
            ) + self.surface.capabilities[1:]))
        with self.assertRaises(ValueError):
            bad = AttackSurface(self.surface.agent_contract_fingerprint, self.surface.capabilities,
            self.surface.actor_identity, self.surface.roles_scopes, {}, self.surface.permitted_targets,
            self.surface.prohibited_targets, self.surface.business_rules, self.surface.state_invariants,
            self.surface.delegation_relationships, self.surface.persistent_state_fields)


    def test_scope_and_evidence_fail_closed(self):
        variant = generate_variants(self.surface, self.candidates[0])[0]
        self.assertTrue(validate_variant_scope(self.surface, variant))
        self.assertFalse(validate_variant_scope(self.surface, replace(variant, bounded_scope_fingerprint="other")))
        self.assertFalse(validate_variant_scope(self.surface, replace(variant, canonical_request={**variant.canonical_request, "target_id": "production-purchase"})))
        evidence = ContainedImpactEvidence({"status": "pending"}, self.candidates[0].forbidden_request, "ALLOWED", {"executed": True, "run_id": "run-1"}, {"status": "changed"}, "effect", 1)
        self.assertFalse(validate_adaptive_evidence(candidate=self.candidates[0], evidence=evidence, capsule=None, run_id="run-1"))

    def test_missing_chain_provenance_is_rejected(self):
        with self.assertRaises(ValueError):
            ChainTransition("missing", {"state": 1}, {"action": 1}, {"state": 2}, {"proven": False})
