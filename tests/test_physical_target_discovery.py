import unittest
from datetime import datetime, timezone
from kimura_assessment.physical_target_discovery import *

class Adapter:
    def __init__(self, identity=None, reach=True, error=None): self.identity, self.reach, self.error = identity, reach, error
    def reachability(self, ip):
        if not self.reach: raise DiscoveryError("unreachable explicit target")
    def collect_identity(self, ip, user):
        if self.error: raise DiscoveryError(self.error)
        return self.identity

def observed(h="kimura", a="aarch64", m="Raspberry Pi 5 Model B Rev 1.1", ip="192.168.2.17", u="kimura"):
    return ObservedIdentity(ip, u, h, a, m)

class DiscoveryTests(unittest.TestCase):
    def run_case(self, adapter):
        return discover_and_verify("192.168.2.17", "kimura", adapter=adapter, clock=lambda: datetime(2026,1,1,tzinfo=timezone.utc))
    def test_success_exact_identity(self): self.assertTrue(self.run_case(Adapter(observed())).identity_verified)
    def test_unreachable_explicit_target(self):
        r=self.run_case(Adapter(None, reach=False)); self.assertFalse(r.identity_verified); self.assertFalse(r.reachability)
    def test_ssh_failure(self):
        r=self.run_case(Adapter(None,error="SSH failure")); self.assertFalse(r.identity_verified); self.assertFalse(r.ssh_connectivity)
    def test_identity_mismatches_never_verify(self):
        for value in (observed(h="wrong"), observed(a="x86_64"), observed(m="Raspberry Pi 4 Model B")):
            self.assertFalse(self.run_case(Adapter(value)).identity_verified)
    def test_missing_or_malformed_identity_evidence(self):
        for error in ("malformed identity evidence", "missing model evidence"):
            r=self.run_case(Adapter(None,error=error)); self.assertFalse(r.identity_verified); self.assertIn(error, r.failure_reason)
    def test_target_substitution_or_stale_identity(self):
        r=self.run_case(Adapter(observed(ip="192.168.2.18"))); self.assertFalse(r.identity_verified); self.assertIn("substitution", r.failure_reason)
    def test_conference_checkpoint_stops_before_baseline(self):
        r=self.run_case(Adapter(observed())).to_conference_result(); self.assertTrue(r["physical_identity_verified"]); self.assertFalse(r["baseline_started"])

if __name__ == "__main__": unittest.main()
