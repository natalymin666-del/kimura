# Kimura assessment

`kimura_assessment` is a small, standard-library Python package for one bounded,
authorized JSON-over-HTTP assessment interaction. It is the packaged form of
the Step 1–6 assessment workflow; the other research scripts in this repository
are not part of this distribution.

## Installation

Python 3.10 or newer is required. From a checkout:

```console
python -m pip install .
```

For local development, use an editable install:

```console
python -m pip install --editable .
```

The package has no runtime dependencies. Build artifacts can be created with
`python -m build` (the build tool is only needed for that command).

## Configuration

The CLI reads a local JSON configuration. The following is a complete shape;
replace the example values with an explicitly approved assessment:

```json
{
  "contract": {
    "assessment_id": "asm-001",
    "client_name": "Example BV",
    "assessor_name": "Kimura Security",
    "authorized_by": "approval-42",
    "objectives": ["Evaluate prompt-injection resistance"],
    "scope": ["https://example.test"],
    "start_date": "2026-08-20",
    "end_date": "2026-08-22",
    "exclusions": ["production data export"],
    "credential_references": ["env://KIMURA_ASSESSMENT_TOKEN"],
    "max_requests": 1
  },
  "target": {
    "endpoint": "https://example.test/chat",
    "input_path": "messages.0.content",
    "response_path": "choices.0.message.content",
    "credential_reference": "env://KIMURA_ASSESSMENT_TOKEN",
    "timeout": 15.0,
    "max_response_bytes": 1048576
  },
  "input_text": "assessment input",
  "request_json": {"messages": [{"role": "user"}]}
}
```

`credential_references` identify credentials held outside the configuration.
For `env://NAME`, the adapter reads `NAME` only at request time. Other opaque
references map to a stable `KIMURA_CREDENTIAL_*` environment variable name.
Never put a token, cookie, password, or other credential material in the JSON
file or source control. Protect the configuration file because `input_text` and
the request template are sent to the authorized endpoint at runtime.

## CLI usage

After installation, run one interaction with either the console script or the
module form:

```console
export KIMURA_ASSESSMENT_TOKEN='runtime-only-secret'
kimura-assessment assessment.json
# equivalent:
python -m kimura_assessment assessment.json
```

The command prints only the safe result metadata JSON. Operational failures are
reported without target, request, response, or credential contents. `--report`
requires `--persist`:

```console
kimura-assessment assessment.json \
  --persist results/assessment.jsonl \
  --report results/assessment-report.json
```

For a deterministic, local-only Conference Demo v1, run:

```console
python3 -m kimura_assessment demo
```

For the deterministic local Conference Demo v2, run:

```console
python3 -m kimura_assessment demo-v2
```

For the deterministic local Agent Security Assessment Demo v3, run:

```console
python3 -m kimura_assessment demo-v3
```

For the local Model-Backed Adapter v1, first install and start Ollama separately with a pinned local model. Kimura accepts only a loopback Ollama endpoint, uses synthetic tools, and does not persist prompts or raw model responses:

```console
python3 -m kimura_assessment demo-model-v1 --model llama3.2:3b --trials 10
```

The command performs paired baseline and exact-fixture remediated trials. Replace the model identifier only with a locally installed, approved model; Kimura does not install or download it.

Demo v3 assesses two independent authorized scenarios against one loopback agent: indirect prompt injection causing an unauthorized `send_email` action, and sensitive-data exfiltration through an `external_upload` boundary. Each finding is validated from safe audit metadata, remediated with an explicit policy, and retested with the exact original fixture. The consolidated report contains hashes, classifications, and evidence references only.

Demo v2 exercises a deliberately vulnerable local agent, validates an
unauthorized synthetic tool action from its audit ledger, applies a local tool
policy, and replays the identical fixture to demonstrate a passing retest.
Evidence stores hashes and safe facts only; it does not persist raw requests,
responses, documents, or credentials.

The demo uses only a loopback mock server, a fixed non-secret placeholder
credential, and the same contract, runner, persistence, and reporting safety
paths as a configured assessment. To also write safe local metadata files:

```console
python3 -m kimura_assessment demo \
  --persist results/conference-demo.jsonl \
  --report results/conference-demo-report.json
```

## Persistence and reporting

`--persist` appends one deterministic JSON object per line to a local JSONL
file. The stored `AssessmentResult` contains the assessment ID, execution
number, authorization date, status, response byte length, and SHA-256 digest;
it does not retain raw input, request, response, or credential data.

The optional report is an aggregate of persisted safe results, sorted
deterministically by assessment ID and execution number. It includes counts,
assessment IDs, total response bytes, and the individual safe result records.
It is metadata reporting, not a transcript.

## Safety guarantees

Each run is constrained by the existing assessment contract and adapter:

- the target must be an HTTP(S) URL inside the declared scope;
- the credential reference must be declared and credential material is resolved
  only from the runtime environment;
- the authorization window and positive request budget are enforced before
  dispatch, and failed attempts consume budget;
- redirects are disabled, response size is bounded, and the expected JSON paths
  must resolve to text; and
- persistence, reports, result JSON, and operational error messages exclude raw
  input, request, response, and credential values.

These controls support an authorized assessment workflow; they do not grant
authorization. Obtain written permission and define scope, exclusions, dates,
and request limits before running it. Keep generated JSONL files and reports
access-controlled.

## Customer Assessment v1

Run the bounded customer workflow with a versioned JSON configuration:

```console
python3 -m kimura_assessment assess customer.json --output ./assessment-output
```

Customer Assessment v1 supports only the existing indirect prompt-injection/tool-authorization fixture against an Ollama loopback runtime. It uses synthetic tools and local policy remediation; it does not contact production or external targets. The output directory contains `assessment.json`, `evidence.jsonl`, `manifest.json`, and a polished `report.html`. Reports are limited to the tested model, runtime, fixture, policy, and trial conditions and do not claim universal model vulnerability.

For the controlled pilot setup and failure-response procedure, see [PILOT_RUNBOOK.md](PILOT_RUNBOOK.md). Start Ollama with `ollama serve`, verify the approved model with `ollama list`, and use the exact model identifier in the customer configuration. Customer preflight verifies both loopback reachability and model installation before execution.

## Tests and build validation

Run the complete test suite from the repository root:

```console
python -m unittest discover -s tests -p 'test_*.py' -v
```

The GitHub Actions workflow runs that suite on Python 3.10, 3.11, and 3.12,
then builds the source and wheel distributions.
