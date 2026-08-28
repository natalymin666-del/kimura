import unittest
from dataclasses import replace

from kimura_assessment.generalization import (SealState, build_generalization_cases,
    design_manifest, seal_generalization_set)


class GeneralizationDesignTests(unittest.TestCase):
    def test_exactly_six_independent_families_and_deterministic_seal(self):
        cases = build_generalization_cases()
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case.family_id for case in cases}), 6)
        sealed = seal_generalization_set(cases)
        self.assertEqual(sealed.seal_state, SealState.SEALED)
        self.assertEqual(sealed.set_sha256, seal_generalization_set(cases).set_sha256)
        self.assertEqual(sealed.ordered_family_ids, tuple(case.family_id for case in cases))

    def test_case_and_ground_truth_mutation_detection(self):
        case = build_generalization_cases()[0]
        sealed_case = replace(case, case_sha256=case.fingerprint)
        with self.assertRaises(ValueError): replace(sealed_case, risk_class="changed")
        sealed = seal_generalization_set()
        with self.assertRaises(ValueError): replace(sealed, ordered_case_ids=("changed",) + sealed.ordered_case_ids[1:]) .verify()

    def test_pair_bindings_and_distinct_observable_semantics(self):
        cases = build_generalization_cases()
        self.assertEqual({case.risk_class for case in cases}, {"privilege-authorization", "sensitive-data", "transaction-boundary", "identity-context", "cross-agent-delegation", "persistent-memory"})
        for case in cases:
            self.assertEqual(case.boundary_pair.safety_contract_fingerprint, case.safety_contract.fingerprint)
            self.assertNotEqual(case.allowed_effect["effect_identity"], case.forbidden_effect["effect_identity"])
            self.assertTrue(case.allowed_effect["effect_count"])
            self.assertTrue(case.forbidden_effect["effect_count"])

    def test_design_manifest_has_no_results_or_hidden_outcome_hints(self):
        manifest = design_manifest()
        self.assertEqual(manifest["observations"], [])
        self.assertFalse(manifest["results_existed_before_seal"])
        self.assertFalse(manifest["outcome_based_selection"])
        self.assertFalse(manifest["family_specific_pass_logic"])
        self.assertEqual(manifest["generic_verifier_branching"], "NONE")
        self.assertNotIn("expected_verdict", str(manifest))
        self.assertNotIn("kimura_verdict", str(manifest))

    def test_sealed_set_rejects_wrong_cardinality_and_case_mutation(self):
        cases = build_generalization_cases()
        with self.assertRaises(ValueError): seal_generalization_set(cases[:-1])
        with self.assertRaises(ValueError): seal_generalization_set(cases[:1] + (replace(cases[1], family_id=cases[0].family_id),) + cases[2:])


if __name__ == "__main__":
    unittest.main()
