# Kimura Design-Partner Pilot Offer

## Purpose

Kimura evaluates whether an AI agent can cross explicitly defined action
boundaries and produce independently verifiable evidence of observable effects.

## Why this is different

Generic red-team testing often asks whether an agent can be persuaded into
unsafe behavior. Kimura tests whether the agent actually crosses a defined
action boundary, then verifies the resulting state or effect independently of
the model's explanation.

## What the customer provides

- Agent/tool interface or sandbox adapter
- Tool schemas and canonical arguments
- Relevant authorization policy, roles/scopes, and business rules
- Observable state interface and reset/rollback method
- Synthetic test identities/data
- Written assessment authorization
- A technical contact role and limitations

## What Kimura does

- Boundary discovery and Safety Contract construction
- Paired allowed/forbidden test sealing
- Contained execution and state-before/state-after measurement
- Causal provenance verification and independent verdicts
- Proof Capsule creation
- Remediation exact forbidden retest
- Paired allowed-function preservation verification

## What the customer receives

- Bounded assessment report
- Confirmed findings and observable impact evidence
- Proof Capsule references
- Inconclusive tests and limitations
- Remediation/retest and allowed-function preservation results

## What Kimura will not do

- Mutate production systems during the initial pilot
- Claim the entire agent is secure or that all vulnerabilities were found
- Provide compliance certification
- Treat model prose as proof of impact

Initial pilots use synthetic or customer-sandbox environments only.

## Pilot success criteria

A pilot is technically successful when Kimura can connect to the bounded agent
interface, establish at least one meaningful approved boundary, execute paired
tests inside containment, independently observe relevant state/effects, produce
evidence-backed verdicts and Proof Capsules, and produce a bounded customer
report. Zero vulnerabilities does not make the pilot unsuccessful when
meaningful boundaries were exercised with valid evidence.

## Next step

Complete the short readiness checklist, scope a bounded pilot, provide the
sandbox/test interface and relevant policy information, approve the boundaries
and Rules of Engagement, and run the assessment.

This is a technical pilot description, not a complete security audit,
compliance certification, safety guarantee, or universal vulnerability claim.
