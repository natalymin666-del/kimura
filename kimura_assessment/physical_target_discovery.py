"""Read-only discovery and identity verification for one explicit Raspberry Pi."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import argparse
import ipaddress
import json
import socket
import subprocess
from typing import Callable, Protocol


EXPECTED_HOSTNAME = "kimura"
EXPECTED_ARCHITECTURE = "aarch64"
EXPECTED_MODEL = "Raspberry Pi 5 Model B Rev 1.1"
SSH_PORT = 22


class DiscoveryError(RuntimeError):
    """A target could not be safely reached or its identity was not verified."""


class ReadOnlyTargetAdapter(Protocol):
    def reachability(self, target_ip: str) -> None:
        """Raise on failure; contact only target_ip."""

    def collect_identity(self, target_ip: str, ssh_user: str) -> "ObservedIdentity":
        ...


@dataclass(frozen=True, slots=True)
class ObservedIdentity:
    target_ip: str
    ssh_user: str
    hostname: str
    architecture: str
    model: str


@dataclass(frozen=True, slots=True)
class IdentityExpectation:
    hostname: str = EXPECTED_HOSTNAME
    architecture: str = EXPECTED_ARCHITECTURE
    model: str = EXPECTED_MODEL


@dataclass(frozen=True, slots=True)
class PhysicalIdentityEvidence:
    target_address: str
    ssh_user: str
    observed_hostname: str | None
    observed_architecture: str | None
    observed_model: str | None
    reachability: bool
    ssh_connectivity: bool
    verification_result: str
    discovery_timestamp: str
    identity_timestamp: str | None
    discovery_result: str
    failure_reason: str | None = None

    @property
    def identity_verified(self) -> bool:
        return self.verification_result == "IDENTITY VERIFIED"

    def to_dict(self) -> dict[str, object]:
        return asdict(self) | {"identity_verified": self.identity_verified}

    def to_conference_result(self) -> dict[str, object]:
        return {
            "phase": "physical_identity_checkpoint",
            "status": "PASS" if self.identity_verified else "FAILED",
            "target_ip": self.target_address,
            "target_kind": "raspberry-pi-5-physical-target",
            "ssh_user": self.ssh_user,
            "physical_target_reached": self.reachability and self.ssh_connectivity,
            "physical_identity_verified": self.identity_verified,
            "observed_hostname": self.observed_hostname,
            "observed_architecture": self.observed_architecture,
            "observed_model": self.observed_model,
            "verification_result": self.verification_result,
            "discovery_timestamp": self.discovery_timestamp,
            "identity_timestamp": self.identity_timestamp,
            "discovery_result": self.discovery_result,
            "failure_reason": self.failure_reason,
            "baseline_started": False,
        }


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _explicit_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("target_ip must be an explicit IPv4 address") from exc
    if address.version != 4:
        raise ValueError("target_ip must be an explicit IPv4 address")
    return str(address)


class SshReadOnlyAdapter:
    """Narrow subprocess/socket adapter; every operation is read-only."""

    def __init__(self, *, port: int = SSH_PORT, timeout: float = 5.0, runner=subprocess.run) -> None:
        if port != SSH_PORT or timeout <= 0:
            raise ValueError("only SSH port 22 and a positive timeout are allowed")
        self.port = port
        self.timeout = timeout
        self._runner = runner

    def reachability(self, target_ip: str) -> None:
        with socket.create_connection((target_ip, self.port), timeout=self.timeout):
            return

    def collect_identity(self, target_ip: str, ssh_user: str) -> ObservedIdentity:
        if not isinstance(ssh_user, str) or not ssh_user or any(char in ssh_user for char in "\x00\n\r@:/ "):
            raise DiscoveryError("SSH user is malformed")
        command = "printf '%s\\n' \"$(hostname)\" \"$(uname -m)\" \"$(cat /proc/device-tree/model)\""
        try:
            completed = self._runner(
                ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(self.timeout)}", f"{ssh_user}@{target_ip}", "--", command],
                check=False, capture_output=True, text=True, timeout=self.timeout + 2,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DiscoveryError(f"SSH failure: {type(exc).__name__}") from None
        if completed.returncode != 0:
            raise DiscoveryError("SSH failure")
        lines = completed.stdout.replace("\x00", "").splitlines()
        if len(lines) != 3 or any(not line.strip() for line in lines):
            raise DiscoveryError("malformed identity evidence")
        return ObservedIdentity(target_ip, ssh_user, *(line.strip() for line in lines))


def discover_and_verify(
    target_ip: str,
    ssh_user: str,
    *,
    adapter: ReadOnlyTargetAdapter,
    expected: IdentityExpectation = IdentityExpectation(),
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> PhysicalIdentityEvidence:
    """Contact exactly one explicit target and return truthful runtime evidence."""

    target_ip = _explicit_ipv4(target_ip)
    started = _timestamp(clock)
    try:
        adapter.reachability(target_ip)
    except Exception as exc:
        return PhysicalIdentityEvidence(target_ip, ssh_user, None, None, None, False, False, "IDENTITY NOT VERIFIED", started, None, "UNAVAILABLE", str(exc))
    try:
        observed = adapter.collect_identity(target_ip, ssh_user)
        if observed.target_ip != target_ip or observed.ssh_user != ssh_user:
            raise DiscoveryError("target substitution or stale identity")
        verified = (observed.hostname == expected.hostname and observed.architecture == expected.architecture and observed.model == expected.model)
        return PhysicalIdentityEvidence(target_ip, ssh_user, observed.hostname, observed.architecture, observed.model, True, True, "IDENTITY VERIFIED" if verified else "IDENTITY NOT VERIFIED", started, _timestamp(clock), "REACHABLE", None if verified else "identity mismatch")
    except Exception as exc:
        return PhysicalIdentityEvidence(target_ip, ssh_user, None, None, None, True, False, "IDENTITY NOT VERIFIED", started, None, "SSH FAILED", str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Perform one read-only explicit Raspberry Pi identity discovery")
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--ssh-user", required=True)
    args = parser.parse_args(argv)
    result = discover_and_verify(args.target_ip, args.ssh_user, adapter=SshReadOnlyAdapter())
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0 if result.identity_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
