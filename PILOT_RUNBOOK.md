# Kimura v0.1 Pilot Runbook

This runbook covers the controlled Customer Assessment v1 pilot. It does not
assess production systems or customer external targets. The only supported
runtime is local Ollama, the target is a synthetic local agent, and the tool
execution is synthetic.

## Prepare the operator environment

- Use Python 3.10, 3.11, or 3.12.
- Install Kimura from the checkout with `python3 -m pip install .`.
- Start Ollama separately with `ollama serve`.
- Confirm the approved model is installed with `ollama list`.
- Use the exact model identifier in `customer.json`.
- Do not put credentials, customer secrets, prompts, or raw model output in the configuration.

Kimura preflight checks that the configured Ollama loopback endpoint is reachable
and that the exact model is installed before assessment execution.

## Prepare the assessment

Create a customer-specific copy of `demo/customer.demo.json`. Set a unique
assessment ID, customer name, written authorization statement/reference,
objectives, exclusions, inclusive start/end dates, request budget, model ID,
and trial count. Keep the supported target, provider, scenario, and fixture
unchanged.

The minimum request budget is `2 * trials + 2`: discovery, baseline trials,
remediation, and exact-fixture retest trials. Authorization must be valid for
the complete run.

## Run

```console
python3 -m kimura_assessment assess customer.json \
  --output ./pilot-output/<assessment-id>
```

Review the preflight lines before allowing the run to continue. A successful
run creates exactly four files: `assessment.json`, `evidence.jsonl`,
`manifest.json`, and `report.html`.

## Respond to failures

- `configuration error`: correct the JSON or obtain corrected authorization.
- `runtime preflight error`: start Ollama or install/select the approved model.
- `model failure`: preserve the authorization window and investigate local
  Ollama/model health before rerunning.
- `adapter failure`: stop and investigate the synthetic local transport.
- `assessment execution failure`: do not bypass date or request-budget controls.
- `assessment result failure`: preserve the failed run context and have Kimura
  review the output/implementation.

A mixed model result is a measured result, not a pass. Deliver the generated
status and limitations exactly as reported.

## Review and deliver

Confirm the assessment ID, model, fixture, authorization, scope, trial counts,
validated impacts, remediation status, exact-fixture retest status, and
manifest artifact hashes. Deliver the four artifacts through an access-
controlled channel. Kimura does not modify a customer production system.
