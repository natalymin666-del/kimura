# Cyber Kimura

**Prove the boundary. Not the promise.**

Kimura is a security validation system for AI agents that tests whether an
agent can actually cross a forbidden action boundary and independently
verifies the resulting state or effect.

Unlike testing focused only on whether a model can be persuaded to produce
unsafe text, Kimura evaluates security-relevant agent actions: tool use,
authorization, identity, targets, arguments, and observable state changes.

## Kimura Boundary Proof Protocol

1. **Executable Safety Contract**
   Defines the permitted action boundary using tool identity, canonical
   arguments, authorization context, initial state, and acceptable resulting
   state.

2. **Paired Boundary Tests**
   Creates structurally similar allowed and forbidden actions so the actual
   security boundary is isolated.

3. **Boundary Discovery**
   Derives candidate boundaries from tools, authorization policy, roles/scopes,
   state semantics, and business rules.

4. **Contained Impact**
   Executes inside synthetic or customer sandbox environments and observes
   state-before/state-after evidence.

5. **Proof Capsule**
   Cryptographically binds assessment scope, test pair, request, execution,
   state/effect evidence, causal provenance, and Kimura's verdict.

6. **Independent Verdict**
   Kimura derives verdicts from observable action/effect evidence rather than
   trusting model explanations.

7. **Exact Retest**
   After remediation, Kimura retests the same forbidden boundary and verifies
   that the corresponding legitimate action still works.

The protocol is provider-neutral and does not require raw chain of thought,
credentials stored by Kimura, or customer-specific verifier code.

## Current Evidence

The sealed local generalization run
([Phase 7.3b result](results/phase-7.3b-generalization-run-1.json)) covered six
materially different boundary families:

- privilege/authorization
- sensitive-data access
- transaction boundaries
- identity/context separation
- cross-agent delegation
- persistent memory/state mutation

Results from that synthetic/local run:

- 6/6 families passed
- allowed-function preservation: 6/6
- forbidden-boundary detection: 6/6
- confirmed impact: 6/6
- false-positive count: 0
- false-negative count: 0
- Proof Capsule verification: 12/12
- causal provenance verification: 12/12
- no risk-class-specific or sample-specific verifier branches were added

These are synthetic/local benchmark results. They are not customer validation
and do not establish universal detection rates.

## Design Partner Pilots

Kimura is technically ready for bounded design-partner pilots with teams
building AI agents that execute real tools/actions.

Initial pilots are restricted to synthetic or customer sandbox environments.
Production mutation is prohibited by default.

Customer agent/tool interface
→ boundary discovery
→ approved Safety Contract
→ paired allowed/forbidden tests
→ contained execution
→ observable impact evidence
→ Proof Capsule
→ remediation
→ exact paired retest

Suitable pilot targets include agent systems involving:

- authorization and privilege boundaries
- sensitive-data access
- transactions or external side effects
- identity/context separation
- delegated capabilities
- persistent memory/state mutation

See the [design-partner pilot offer](pilot/design-partner-offer.md),
[intake template](pilot/intake-template.json), and
[onboarding checklist](pilot/onboarding-checklist.md).

## Limitations

Kimura does not currently claim:

- that an assessed agent is universally secure
- complete vulnerability coverage
- production validation
- compliance certification
- guaranteed safety
- customer validation until an actual customer assessment has occurred

Findings apply only to the tested boundary, agent version, environment,
policy, identities, targets, and evidence available for that assessment.

## Installation

Python 3.10 or newer is required:

```console
python -m pip install .
```

For local development:

```console
python -m pip install --editable .
```

The package has no runtime dependencies. Build artifacts can be created with
`python -m build` when the build tool is installed.

## Local Development and Testing

Run the complete local test suite:

```console
python -m unittest discover -s tests -p 'test_*.py' -v
```

The repository also uses pytest in local validation:

```console
python -m pytest
```

The GitHub Actions workflow runs the test suite on Python 3.10, 3.11, and
3.12, then builds source and wheel distributions.

For the controlled pilot setup and failure-response procedure, see
[PILOT_RUNBOOK.md](PILOT_RUNBOOK.md).

## Local Demonstrations

The repository includes deterministic local demonstrations for the Boundary
Proof workflow:

```console
python3 -m kimura_assessment demo
python3 -m kimura_assessment demo-v2
python3 -m kimura_assessment demo-v3
python3 -m kimura_assessment.conference_demo
```

These demonstrations use synthetic fixtures and contained/local execution.
They do not validate a customer system or establish production impact.

The local design-partner package includes a
[synthetic demonstration report](pilot/demo-pilot-report.html). It is labeled
as demonstration evidence and is not customer validation.

## Earlier LLM Security Research

This repository also preserves earlier prompt-injection and LLM red-team
research, including historical experiments and write-ups. That work is
retained as research context and evidence history; it is not the primary
description of the current Kimura product.

Examples include:

- [cyber-kimura-llm-writeup.md](cyber-kimura-llm-writeup.md)
- [PHASE_5.2A_AGENTIC_RISK_MATRIX_V1.md](PHASE_5.2A_AGENTIC_RISK_MATRIX_V1.md)
- [PILOT_RUNBOOK.md](PILOT_RUNBOOK.md)

Historical artifacts are not rewritten when product positioning changes.
