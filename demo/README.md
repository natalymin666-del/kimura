# Kimura Sales Demo Package v1

This is a short live demonstration of the existing Customer Assessment v1
workflow. It assesses one model-backed agent against one approved indirect
prompt-injection/tool-authorization fixture, applies local policy remediation,
and replays the exact fixture.

## Prerequisites

- Python 3.10 or newer
- This repository checkout
- Ollama running locally on http://127.0.0.1:11434
- llama3.2:3b already installed in Ollama

Kimura does not install, download, or select a remote model. Verify the model
with: ollama list

The model output can vary by runtime or model version. The assessment result,
not this document, is authoritative for the observed outcome.

## Run

~~~console
python3 -m kimura_assessment assess demo/customer.demo.json \
  --output ./demo-output
~~~

Typical runtime is roughly 30–90 seconds, depending on local hardware and
Ollama latency. Allow extra time for first model load.

## Generated artifacts

- assessment.json: safe structured report and measured counts
- evidence.jsonl: safe evidence records with digests only
- manifest.json: artifact, model, fixture, and evidence metadata
- report.html: offline customer-facing report

The CLI summary and all numerical outcomes are derived from the generated
assessment result. No successful finding or count is hardcoded.

## Safety boundaries

- Ollama and the assessment target are loopback-only.
- The target is a synthetic local agent.
- The only tool is a synthetic send_email action.
- No email, network request, or other external side effect occurs.
- The configuration contains no real credentials or customer data.
- Credentials are reference-only and a synthetic placeholder is supplied inside
  the existing workflow.
- Raw prompts, retrieved content, provider responses, secrets, and sensitive
  tool arguments are not persisted or printed by the CLI summary.

## What this demonstrates

Kimura separates the model proposed action, tool authorization decision, local
simulated execution, validated impact, remediation, and exact retesting. It
shows how a bounded assessment produces safe evidence and a professional report.

## What this does not demonstrate

This is not a production compromise, a real customer-target test, or proof that
all AI agents or all versions of a model are vulnerable. It does not prove
universal model behavior, complete security, or absence of risk outside the
tested model, runtime, fixture, policy, and trial conditions.

If the live model produces no finding or a mixed result, report that result
accurately. Do not substitute expected demo language for generated output.
